FROM python:3

RUN pip install jupyterlab --quiet
RUN pip install unicorn --quiet
RUN pip install keystone-engine --quiet

WORKDIR /usr/src/app

RUN export PYTHONPATH="/usr/local/share/jupyter/kernels/arm_kernel" 

