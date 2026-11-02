//! Preparing a program's environment. This is where "use, never read" is decided: real values
//! leave the broker only for names the caller listed, and only after a fresh touch.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Weak};

use zeroize::Zeroizing;

use super::Broker;
use super::handlers::{resolve_space, space_name};
use super::policy::{Action, Caller};
use super::proxy::{self, Proxy, Substitution};
use crate::item::{Kind, Secret};
use crate::store::log::hex;
use crate::{Error, Result, crypto};

const PLACEHOLDER_PREFIX: &str = "lv_ph_";

/// A prepared run. Dropping it stops the proxy and removes its trust files.
#[derive(Debug)]
pub struct Run {
    proxy: Option<Arc<Proxy>>,
    dir: PathBuf,
}

/// The broker's view of a run that holds secrets, so it can end when the access behind it does.
/// A run belongs to its client's connection, so this does not keep it alive.
#[derive(Debug)]
pub(super) struct LiveRun {
    pub grant: Option<String>,
    pub proxy: Weak<Proxy>,
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The run, the program's environment, and real values to scrub from its output.
pub(super) type Prepared = (Run, Vec<(String, String)>, Vec<String>);

struct Plan {
    real: Vec<(String, Zeroizing<String>)>,
    proxied: Vec<(String, Zeroizing<String>, Vec<String>)>,
}

impl Broker {
    fn plan_run(&self, caller: &Caller, space: Option<&str>, command: &str, requested: &[String], all: bool) -> Result<Plan> {
        let (id, target, items) = {
            let core = self.unlocked()?;
            let id = resolve_space(&core.vault, caller, space)?;
            let items: Vec<_> = core.vault.items(&id)?.into_iter().filter(|item| item.meta.kind == Kind::Env).collect();
            (id, space_name(&core.vault, &id), items)
        };
        if let Some(missing) = requested.iter().find(|name| !items.iter().any(|item| item.meta.name == **name)) {
            return Err(Error::NotFound(missing.clone()));
        }
        let wants_real = |name: &str, hosts: &[String]| requested.iter().any(|wanted| wanted == name) || (all && hosts.is_empty());
        let blocked: Vec<&str> = items
            .iter()
            .filter(|item| item.meta.hosts.is_empty() && !wants_real(&item.meta.name, &item.meta.hosts))
            .map(|item| item.meta.name.as_str())
            .collect();
        if !blocked.is_empty() {
            return Err(Error::NoHost(blocked.join(", ")));
        }

        let names: Vec<&str> =
            items.iter().filter(|item| wants_real(&item.meta.name, &item.meta.hosts)).map(|item| item.meta.name.as_str()).collect();
        self.check(
            caller,
            if names.is_empty() {
                Action::RunProxied { command, space: &target }
            } else {
                Action::RunWithValues { command, space: &target, names: &names }
            },
        )?;

        let mut plan = Plan { real: Vec::new(), proxied: Vec::new() };
        let mut core = self.open_core()?;
        for item in items {
            let Ok(secret) = core.vault.secret(&id, &item.id) else { continue };
            let Secret::Env { value } = &secret else { continue };
            let value = Zeroizing::new(value.clone());
            if wants_real(&item.meta.name, &item.meta.hosts) {
                plan.real.push((item.meta.name, value));
            } else {
                plan.proxied.push((item.meta.name, value, item.meta.hosts));
            }
        }
        core.vault.record(if plan.real.is_empty() { "run" } else { "run-with-values" }, command, caller.name())?;
        Ok(plan)
    }

    pub(super) fn start_run(&self, caller: &Caller, space: Option<&str>, command: &str, requested: &[String], all: bool) -> Result<Prepared> {
        let plan = self.plan_run(caller, space, &super::grants::sanitize(command), requested, all)?;

        let dir = self.home.join("run").join(hex(&crypto::random::<8>()));
        crate::store::private_dir(&dir)?;
        let mut run = Run { proxy: None, dir };
        let mut env: Vec<(String, String)> = plan.real.iter().map(|(name, value)| (name.clone(), value.to_string())).collect();
        let scrub = plan.real.iter().map(|(_, value)| value.to_string()).collect();

        if !plan.proxied.is_empty() {
            let mut substitutions = Vec::with_capacity(plan.proxied.len());
            for (name, secret, hosts) in plan.proxied {
                let placeholder = format!("{PLACEHOLDER_PREFIX}{}", hex(&crypto::random::<24>()));
                env.push((name, placeholder.clone()));
                substitutions.push(Substitution { placeholder, secret, hosts });
            }
            let proxy = proxy::start(self.runtime.handle(), &self.home, substitutions)?;
            let ca = run.dir.join("ca.pem");
            let bundle = run.dir.join("bundle.pem");
            crate::store::write_private(&ca, proxy.ca_pem.as_bytes())?;
            crate::store::write_private(&bundle, proxy::trust_bundle(&proxy.ca_pem).as_bytes())?;

            let url = format!("http://127.0.0.1:{}", proxy.port);
            let (ca, bundle) = (ca.display().to_string(), bundle.display().to_string());
            for name in ["HTTPS_PROXY", "https_proxy"] {
                env.push((name.to_owned(), url.clone()));
            }
            for name in ["NO_PROXY", "no_proxy"] {
                env.push((name.to_owned(), "localhost,127.0.0.1,::1".to_owned()));
            }
            env.push(("NODE_USE_ENV_PROXY".to_owned(), "1".to_owned()));
            for name in ["NODE_EXTRA_CA_CERTS", "DENO_CERT"] {
                env.push((name.to_owned(), ca.clone()));
            }
            for name in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"] {
                env.push((name.to_owned(), bundle.clone()));
            }
            let proxy = Arc::new(proxy);
            let grant = match caller {
                Caller::Anyone | Caller::App => None,
                Caller::Session(grant) => Some(grant.id.clone()),
            };
            // The access behind this run may have ended while it was being set up, and a run
            // nothing knows about would outlive that. Dropping `proxy` here erases its secrets.
            let mut core = self.open_core()?;
            if grant.as_ref().is_some_and(|id| !core.grants.list().iter().any(|live| live.id == *id)) {
                return Err(Error::NotApproved("that session has ended; ask for a new grant"));
            }
            core.runs.push(LiveRun { grant, proxy: Arc::downgrade(&proxy) });
            drop(core);
            run.proxy = Some(proxy);
        }
        Ok((run, env, scrub))
    }
}
