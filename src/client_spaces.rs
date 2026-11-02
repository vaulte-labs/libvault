//! Spaces: listing, making, renaming and removing them.

use super::{Client, UNEXPECTED};
use crate::Result;
use crate::protocol::{Request, Response};

impl Client {
    pub fn spaces(&mut self) -> Result<Vec<String>> {
        match self.call(Request::Spaces)? {
            Response::Spaces { spaces } => Ok(spaces),
            _ => Err(UNEXPECTED),
        }
    }

    /// Makes a new, empty space, and returns its name as kept: trimmed. A name that differs from
    /// one in use only by case is refused. A space removed before comes back, with its history.
    pub fn create_space(&mut self, name: &str) -> Result<String> {
        match self.call(Request::SpaceAdd { name: name.to_owned() })? {
            Response::Space { name } => Ok(name),
            _ => Err(UNEXPECTED),
        }
    }

    /// Renames a space, after a touch, returning the new name as kept. Grants and the items in it
    /// carry over. The first space, where everything goes when no space is named, keeps its name.
    pub fn rename_space(&mut self, name: &str, to: &str) -> Result<String> {
        match self.call(Request::SpaceRename { name: name.to_owned(), to: to.to_owned() })? {
            Response::Space { name } => Ok(name),
            _ => Err(UNEXPECTED),
        }
    }

    /// Removes an empty space, after a touch. A space holding anything is refused with a count of
    /// what it holds, so nothing is lost. `create_space` with the same name brings it back.
    pub fn remove_space(&mut self, name: &str) -> Result<()> {
        self.call(Request::SpaceRemove { name: name.to_owned() }).map(drop)
    }
}
