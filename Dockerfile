FROM node:20-slim
RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Caydiid-upload.zip .
RUN unzip -o Caydiid-upload.zip && rm Caydiid-upload.zip
COPY server.js .
ENV NODE_ENV=production PORT=8080
EXPOSE 8080
CMD ["node", "server.js"]
