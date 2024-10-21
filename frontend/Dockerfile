FROM node:18-alpine

WORKDIR /frontend

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3000

# Start the React development server
CMD ["npm", "start"]
