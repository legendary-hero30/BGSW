# DEMO: deliberately unsafe. Findings expected from hadolint / trivy config.
FROM node:14
ENV NODE_ENV=production
ENV API_TOKEN=demo-not-a-real-token
WORKDIR /app
RUN apt-get update && apt-get install -y curl wget
ADD https://example.com/install.sh /tmp/install.sh
COPY . .
RUN npm install
EXPOSE 22 3000
CMD ["node", "src/cli.js"]
