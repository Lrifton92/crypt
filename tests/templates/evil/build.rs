// Generates the template metadata (name, functions, and the tags and links in Cargo.toml) that the
// Ootle tooling reads when the template is published.
fn main() {
    if let Err(e) = tari_ootle_template_build::TemplateMetadataBuilder::new().build() {
        panic!("could not generate the Crypt template metadata: {e:?}");
    }
}
