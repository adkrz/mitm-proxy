GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1


HTTP/1.1 200 OK
Content-Encoding: gzip
Cache-Control: max-age=604800
Content-Type: text/html
Date: Sat, 18 Mar 2017 06:28:39 GMT
Etag: "359670651+gzip"
Expires: Sat, 25 Mar 2017 06:28:39 GMT
Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT
Server: ECS (cpm/F9D5)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 606
Connection: close

� ;�R �TA��0��W�ri]��S�V @���1k��Z��$�6���q۽���@+���l�I�I��s�PzUe���Bf�'��+�>���+�OF	�I4h��^@^
�ЧA�p@�M���u��j��������*<�|ԅߎP���P�-�6�O��$}�Jl)ǰ_,�4yU�rQazw�r���t.�s���3�z�_������2�Melϋ5����%�t뫪R���t3��:�|�Q��]���V-z�|�Y3*���rKp�5th��"��C���NH����v��OOyޣ�xs�����V��$��X�6�BR�b�C��PqE���K�<�	�G�כ7����E(17Vx2�U�S��
%	x��)�d�����e��O&�4/䤘���~��Oi�s�X�dW�7��#�u�"��y\$]j<�L�r�˻'�ɪ�Vg?Kr {=��΋]E��^x;�ƱXTU��]�[�{��s+�e���9�g���]����H�4���#�KA��'�Z�����*r��$�G�	��4�n�8���㊄+c���E�hA��X���������L��RIt�[4\o����  
GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
If-Modified-Since: Fri, 09 Aug 2013 23:54:35 GMT
If-None-Match: "359670651+gzip"
Cache-Control: max-age=0


HTTP/1.1 304 Not Modified
Cache-Control: max-age=604800
Date: Sat, 18 Mar 2017 06:33:43 GMT
Etag: "359670651+gzip"
Expires: Sat, 25 Mar 2017 06:33:43 GMT
Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT
Server: ECS (cpm/F9D5)
Vary: Accept-Encoding
X-Cache: HIT
Connection: close


GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
If-Modified-Since: Fri, 09 Aug 2013 23:54:35 GMT
If-None-Match: "359670651+gzip"
Cache-Control: max-age=0


HTTP/1.1 304 Not Modified
Cache-Control: max-age=604800
Date: Sat, 18 Mar 2017 06:35:06 GMT
Etag: "359670651+gzip"
Expires: Sat, 25 Mar 2017 06:35:06 GMT
Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT
Server: ECS (cpm/F9D5)
Vary: Accept-Encoding
X-Cache: HIT
Connection: close


