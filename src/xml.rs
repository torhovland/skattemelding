use std::{borrow::Cow, io::BufWriter};

use anyhow::{anyhow, Result};
use xmltree::{Element, EmitterConfig, XMLNode};

pub trait XmlElement {
    fn child(&self, name: &str) -> Result<&Element>;
    fn format(&self) -> Result<String>;
    fn text(&self) -> Result<Cow<str>>;
}

impl XmlElement for Element {
    fn child(&self, name: &str) -> Result<&Element> {
        tracing::debug!("Looking for {name} in: {self:?}");

        self.get_child(name)
            .ok_or_else(|| anyhow!(format!("Did not find {name} in XML element")))
    }

    fn format(&self) -> Result<String> {
        let mut cfg = EmitterConfig::new();
        cfg.perform_indent = true;

        let mut buf = BufWriter::new(Vec::new());
        self.write_with_config(&mut buf, cfg)?;
        let bytes = buf.into_inner()?;
        Ok(String::from_utf8(bytes)?)
    }

    fn text(&self) -> Result<Cow<str>> {
        self.get_text()
            .ok_or_else(|| anyhow!("Did not find text in XML element"))
    }
}

pub trait XmlNode {
    fn element(&self) -> Result<&Element>;
}

impl XmlNode for XMLNode {
    fn element(&self) -> Result<&Element> {
        self.as_element()
            .ok_or_else(|| anyhow!("The node is not an XML element"))
    }
}

pub fn to_xml(s: &str) -> Result<Element> {
    Ok(Element::parse(s.as_bytes())?)
}
