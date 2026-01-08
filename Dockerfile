FROM python:3.13-slim
LABEL org.opencontainers.image.vendor="JDB-NET"
WORKDIR /app
COPY . /app
ARG VERSION=unknown
ENV APP_VERSION=${VERSION}
RUN pip install -r requirements.txt \
    && apt-get update \
    && apt-get install curl -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64 \
    && chmod +x tailwindcss-linux-x64 \
    && mv tailwindcss-linux-x64 tailwindcss \
    && ./tailwindcss -i ./static/css/input.css -o ./static/css/output.css --content "./templates/*.html,./static/js/*.js" --minify \
    && rm tailwindcss
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]