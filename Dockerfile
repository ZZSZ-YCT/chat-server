FROM node:18-alpine

WORKDIR /app

# 复制 package 文件并安装依赖
COPY package*.json ./
RUN npm install

# 复制所有代码
COPY . .

# 编译 TypeScript
RUN npm run build

EXPOSE 8080
CMD ["node", "dist/server.js"]