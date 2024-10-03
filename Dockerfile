# Используем базовый образ с Go для этапа сборки
FROM golang:1.23.1 as builder

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем go.mod и go.sum для установки зависимостей
COPY checker/go.mod checker/go.sum ./

# Копируем локальный модуль API в контейнер
COPY ../api /app/api

# Загружаем зависимости
RUN go mod download

# Копируем весь исходный код
COPY . .

# Собираем бинарный файл на основе main.go
RUN go build -o checker_server ./cmd/main.go

# Используем минимальный образ для запуска бинарного файла
FROM debian:buster-slim

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем собранный бинарник из предыдущего этапа
COPY --from=builder /app/checker_server .

# Указываем порт, который будет слушать сервер
EXPOSE 50051

# Указываем команду для запуска сервера
CMD ["./checker_server"]
