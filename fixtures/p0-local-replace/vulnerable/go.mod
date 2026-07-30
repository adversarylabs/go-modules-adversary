module example.test/p0-local-replace-vulnerable

go 1.24

require example.com/dependency v1.0.0

replace example.com/dependency => ../dependency
