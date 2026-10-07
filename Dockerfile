FROM node:20-slim
WORKDIR /app
COPY . .
ENV NODE_ENV=production PORT=8080
EXPOSE 8080
CMD ["node", "server/server.js"]
