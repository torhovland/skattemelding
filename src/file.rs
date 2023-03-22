use std::fs;

use anyhow::Result;

pub fn read_skattemelding(year: i32) -> Result<String> {
    read_file("skattemelding.xml", year)
}

pub fn read_naeringsspesifikasjon(year: i32) -> Result<String> {
    read_file("naeringsspesifikasjon.xml", year)
}

fn read_file(name: &str, year: i32) -> Result<String> {
    Ok(fs::read_to_string(format!("{}/{}", year, name))?)
}
