use std::borrow::Cow;

use anyhow::{anyhow, Result};
use xmltree::Element;

pub trait Xml {
    fn child(&self, name: &str) -> Result<&Element>;
    fn text(&self) -> Result<Cow<str>>;
}

impl Xml for Element {
    fn child(&self, name: &str) -> Result<&Element> {
        self.get_child("name")
            .ok_or_else(|| anyhow!(format!("Did not find {name} in XML element")))
    }

    fn text(&self) -> Result<Cow<str>> {
        self.get_text()
            .ok_or_else(|| anyhow!("Did not find text in XML element"))
    }
}
