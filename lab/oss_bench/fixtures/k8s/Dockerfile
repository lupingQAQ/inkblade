FROM python:3.12
USER root
RUN pip install flask==0.12.2 pillow==9.0.0
ENV OPENAI_API_KEY=sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
COPY . /app
CMD ["python", "/app/train.py"]
