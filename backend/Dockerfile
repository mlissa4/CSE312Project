FROM node:18

WORKDIR /backend

COPY package.json ./
RUN npm install

COPY . .

# This is for the wait script 
ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

EXPOSE 5000

# Use the nodemon dev script for watching code changes
CMD /wait && npm run start
