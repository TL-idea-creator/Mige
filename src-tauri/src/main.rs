// 仅在 Windows 的发布版隐藏控制台窗口（其它平台编译时该属性会被忽略）
#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

fn main() {
    mige_lib::run()
}
