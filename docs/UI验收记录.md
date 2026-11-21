# 手机清单界面验收

本轮把交互原型落成样本应用。检测仍是已有报告，不把原型里的演示值写进界面。未实现的拟新增项不出现。

设备：AVD virtprobe，API 35，x86_64，ranchu，`emulator-5554`。没有崩溃。

`33-ui-home.png` 和 `36-ui-restricted-detail.png` 标题与状态栏时间重叠，状态栏图标在浅底上发白。那两张不能当作界面通过。下面的截图是补上安全区之后重装的整屏。

API 35 目标会把内容画到系统栏下面，原来的深色 `statusBarColor` 又让时间保持白色。现在窗口走 edge-to-edge，状态栏和导航栏用深色图标，内容用 `safeDrawing` 与输入法 insets 的并集让开，不隐藏系统栏。

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| 首屏避开状态栏，图标可读，无安全分 | 通过。标题在时间下方 | `50-ui-home-insets.png` |
| 详情返回与标题避开状态栏 | 通过 | `53-ui-detail-insets.png` |
| 筛选弹层，重置和完成可见；滑到底能看到「系统信任」，不被手势条挡住 | 通过 | `51-ui-filter-insets.png`、`60-ui-filter-scrolled.png` |
| 无法检查列表与返回后仍是该筛选 | 通过 | `52-ui-restricted-insets.png`、`55-ui-back-filter.png` |
| 技术详情可滑到原始证据末尾，上一项在手势条上方 | 通过 | `54-ui-tech-bottom.png` |
| 点进较低的一项再返回，该项仍在视野里 | 通过。QEMU 内核与启动属性 | `59-ui-scroll-restored.png` |
| 输入页避开状态栏 | 通过 | `56-ui-input-insets.png` |
| 软键盘出现时结论仍可见，导航在键盘上方；收起后建议和技术详情回来 | 通过。输入 hi 仍是软键盘，不是注入 | `57-ui-keyboard.png`、`58-ui-keyboard-gone.png`、`61-ui-keyboard-scrolled.png` |
| 名称搜索、分组收起、副屏详情 | 仍以上一轮功能截图为准，逻辑未改 | `39-ui-search.png`、`45-ui-collapsed.png`、`49-ui-display-detail.png` |
| 重新扫描防重入 | 按钮在扫描中禁用。扫描通常不到一秒，没有稳定截到「扫描中」 | 受限 |

本轮环境复测见双层验证矩阵末节。代理写入 `10.0.2.2:8080` 后仍是未发现线索；清除时要写 `:0` 再删，否则进程仍读到旧代理。最终冷启动为「代理=无」。`/system/xbin/su` 仍是 `rwsr-x---`，应用侧无法检查。
