FROM debian:bookworm

RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y python3 python3-pip python3-wheel python3-setuptools \
    git jq wget

RUN mkdir -p /srv
ADD . /srv/kerbside
ADD loadtests/latency/makeconsole.sh /srv/makesonsole.sh
ADD loadtests/latency/cleanupconsoles.sh /srv/cleanupconsoles.sh

RUN git clone https://github.com/openstack/openstacksdk /srv/openstacksdk
RUN git clone https://github.com/openstack/python-openstackclient \
    /srv/python-openstackclient

RUN pip install --break-system-packages bindep yq

RUN cd /srv/openstacksdk && pip install --break-system-packages -e .
RUN cd /srv/python-openstackclient && pip install --break-system-packages -e .

RUN cd /srv/kerbside && apt-get install -y $(bindep --brief)
RUN cd /srv/kerbside && pip install --break-system-packages -e .
RUN cd /srv/kerbside/testclient && pip install --break-system-packages -e .

CMD /srv/makeconsole.sh