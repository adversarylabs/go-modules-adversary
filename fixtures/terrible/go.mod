module example.test/modules-terrible

go 1.24

replace example.com/dependency => ../dependency
replace example.com/other => example.com/fork main
exclude example.com/legacy v1.2.0
