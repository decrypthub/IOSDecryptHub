# release-notes

发版说明目录。文件名必须是 **`<版本号>.md`**（不带 `v`），例如 `1.27.6.md`。

`release.yml` 与 `scripts/publish_release.sh` 在创建 Release 时：

1. 先找 `.github/release-notes/<version>.md` —— **找到就用它**；
2. 找不到就用上一个 tag 到当前的提交标题自动生成（质量一般，仅作兜底）。

所以想写出像样的更新说明，就在发版前把 `1.27.6.md` 放进这个目录一起提交。

写法参考历史 Release（`gh release view v1.27.5`），建议分「重要修复 / 新增 / 验证 / 说明」几段，
并把真机验证结果写进「验证」段。
