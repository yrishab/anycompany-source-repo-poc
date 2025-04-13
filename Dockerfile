# FROM python:3.9-slim
FROM python:3.9-slim

ENV AWS_REGION="us-east-1"
ENV USER_POOL_ID="us-east-1_9gs1hY0G3"
ENV APP_CLIENT_ID="2pgkrojkp9g0rlvnajt81eghg7"
ENV APP_CLIENT_SECRET="j97rebt99irv25ja62309rmfu7sf0pr9kmra4aevukaqan01bog"
ENV COGNITO_DOMAIN="auth.yrishab.people.aws.dev"
ENV REDIRECT_URI="https://26oj1y6xsa.execute-api.us-east-1.amazonaws.com/prod/"
ENV API_GATEWAY_URL="https://26oj1y6xsa.execute-api.us-east-1.amazonaws.com/prod"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 80

CMD ["python", "app.py"]
