Copy example_conf.py to conf.py

Edit conf.py to match your setup

Make a needed HTML page:
./make_opbyuid_html.py conf > html/opbyuid.html

The run the service
./rp.py -t -k conf
