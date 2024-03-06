FROM python:3.8

RUN mkdir /opt/grom-admin
WORKDIR /opt/grom-admin
ADD requirements.txt /opt/grom-admin/
RUN pip3 install -r requirements.txt
ADD startup.py app.conf /opt/grom-admin/
ADD src /opt/grom-admin/src
CMD python3 startup.py -c app.conf
