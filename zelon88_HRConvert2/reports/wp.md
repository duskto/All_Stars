## 漏洞详情
这个前认证RCE能够被触发，但是字符过滤太多，无前端回显，不好利用，修改exp中的`` "userconvertfilename": "`whoami`" ``即可