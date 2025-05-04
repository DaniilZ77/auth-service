# Auth Server

## Конфигурация

```yaml
http_port: 0.0.0.0:8081
jwt_secret: secret
access_token_ttl: 2m
refresh_token_ttl: 10h
db_url: postgres://postgres:postgres@auth-postgres:5432/auth
log_level: info
webhook_url: http://localhost:9090/webhook // вебхук, на который отправляется информация, если ip адреса не совпадают
```

**Также обязательно нужно создать .env**:

```.env
POSTGRES_PASSWORD=postgres
POSTGRES_USER=postgres
POSTGRES_DB=auth
CONFIG_PATH=./config/auth.yaml
```

## Запуск

1. Создать `.env` с параметрами выше
2. Выполнить команду:
    ```bash
    $ docker-compose -f docker-compose.yml up
    ```

**По дефолту сервер запустится на порту `8081`, чтобы посмотреть `swagger`, нужно перейти на `http://localhost:8081/swagger`.**