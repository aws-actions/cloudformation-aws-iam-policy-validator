# FROM public.ecr.aws/lambda/python:3.10
FROM python:3.10
# Install cfn-policy-validator
RUN  pip install cfn-policy-validator==0.0.34

COPY main.py /main.py

ENTRYPOINT ["python3", "/main.py"]
