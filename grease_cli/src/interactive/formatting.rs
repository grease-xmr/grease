use std::fmt::Write;

use anyhow::Result;
use prettytable::{
    format::{LinePosition, LineSeparator, TableFormat},
    row, Cell, Row, Table,
};
use qrcode::{render::unicode, QrCode};

fn markdown_format() -> TableFormat {
    prettytable::format::FormatBuilder::new()
        .column_separator('|')
        .borders('|')
        .separator(LinePosition::Title, LineSeparator::new('-', '|', '|', '|'))
        .padding(1, 1)
        .build()
}

fn markdown_style(table: &mut Table) {
    table.set_format(markdown_format());
}

pub fn format_server_id_with_qr_code(server_info: &String) -> String {
    let qr_link = format!("server details go here: {server_info}");
    let code = QrCode::new(qr_link)
        .map(|code| {
            code.render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Dark)
                .light_color(unicode::Dense1x2::Light)
                .quiet_zone(false)
                .build()
        })
        .unwrap_or_default();
    code
}
