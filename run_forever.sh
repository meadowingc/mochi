#!/usr/bin/env bash

# run forever, even if we fail
while true; do
    git pull
    npx @tailwindcss/cli -i ./main.css -o ./assets/css/bundled_styles.css --minify
    go build -tags release -o mochi
    ./mochi
    sleep 1
done
