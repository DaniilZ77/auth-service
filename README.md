# Auth Server

## Конфигурация

```yaml
http_port: 0.0.0.0:8081
jwt_secret: secret
access_token_ttl: 2m
refresh_token_ttl: 10h
db_url: postgres://postgres:postgres@auth-postgres:5432/auth
log_level: info
webhook_url: http://localhost:9091/webhook // вебхук, на который отправляется информация, если ip адреса не совпадают, при запуске докера также поднимается сервер с этим эндпоинтом и логирует тело запроса
```

**Также обязательно нужно создать .env в корне проекта**:

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

## Краткое описание

- Часть сервиса аутентификации на языке Golang
- Протестирован сервисный слой с помощью mockery
- Сделан swagger и docker
- В качестве бд используется `PostgreSQL` и драйвер `pgx`
- Используется `jwt` для `access token` и `uuid` в формате `base64` для `refresh token`
- При `login` выдается `access token` и `refresh token`
- При `refresh` принимается только эта пара, иначе будет выдана ошибка 400, пара валидируется и если все впорядке, то выдается новая пара токенов и в бд `is_revoked` старой сессии становится `true`.
- В `payload of access token` хранится следующая полезная информация:
    ```json
    {
        "exp": 12345,
        "user_id": "7940c5a6-55d6-4489-a289-ab4d4955d459",
        "session_id": "d36b091b-a548-4b26-bb66-f2c45f5b7538"
    }
    ```
    - `exp` - время, до которого токен валиден
    - `user_id` - uuid пользователя
    - `session_id` - uuid сессия, которая еще хранится в бд и привязана к refresh token, это позволяет понимать, той ли парой мы рефрешим токены или нет
- Алгоритм подписи `SHA512`, `access token` в бд соответсвенно **не хранится**.
- При `logout` `session_id` добавляется в `blacklist`, который у меня релизован, как мапа под `rw` мьютексом. Также в бд `is_revoked` (отозван ли токен) становится `true`.
- Если в `refresh` `User-Agent` другой, то пара соответсвенно становится невалидной, то есть вызывается `logout` из предыдущего пункта и возвращается клиенту ошибка.
- Если `ip` адрес запроса другой (порт не считается), то на `webhook` отправляется `post` запрос со следующей информацией (с повторением попыток, если ответ не 200, и паузой между попытками):
    ```json
    {
        "old_ip": "184.111.111.249",
        "new_ip": "14.79.253.192",
        "user_id": "2f12c5cd-eef3-40d8-a8ae-0d8f55a15aab"
    }
    ```
- `me` эндпоинт возвращает `uuid` пользователя
- `ping` - проверка, что сервер жив
- Также есть 3 `middleware`:
    - `loggingMiddlerware` - просто логирует мета о запросе
    - `protectedMiddleware` - достает токен из хедера `authorization` (можно токен передавать без `Bearer`), валидирует еге, также вызывает `CheckSession`, которая проверяет наличие `session_id` в блэклисте и если его там нету то кладет всю информацию из токена в контекст и передает в следующий хэндлер. Иначе возвращаем `401`.
    - `injectionMiddleware` - то же самое, что и предыдущий, только если токен просрочен или в блэклисте, то все равно кладем информацию из токена в контекст и передаем в следующий запрос, не возвращая `401`.

## База данных (схема)

- В базе находится только одна таблица:
    ```sql
    create table if not exists sessions (
        id uuid primary key not null default uuid_generate_v4(),
        refresh_token_hash varchar(128) not null,
        is_revoked boolean not null default false,
        user_agent varchar(256) not null,
        ip_address varchar(64) not null,
        expiry timestamp not null,
        updated_at timestamp not null default now(),
        created_at timestamp not null default now()
    );
    ```
    - `id` - `session_id` (`uuid` сессии)
    - `refresh_token_hash` - `bcrypt` хэш рефреш токена
    - `is_revoked` - поле, отозван ли токен (при `logout` или `refresh` например)
    - `user_agent` - `user agent` запроса, с которого получили токен
    - `ip_address` - айпи адрес, с которого получили токен
    - `expiry` - время, когда истечет срок валидности токена в `utc`
    - `updated_at` - время обновления записи
    - `created_at` - время создания записи

## Структура проекта

- `./cmd` - точки входа приложений (`main`)
- `./config` - конфиг файлы в формате `yaml`
- `docs` - сгеенрированная с помощью `swaggo` сваггер документация
- `./internal/app` - инициализация приложения, создание сервиса, слоя работы с данными и `http` сервера
- `./internal/config` - чтения конфига из `./config`
- `./internal/data` - миграции
- `./internal/domain/models` - модели базы данных и сервисного слоя
- `./internal/models` - модели, которые отправляются на фронт (клиенту) и принимаются от клиента
- `./internal/http` - `middleware`, хэндлеры, которые обрабатывают все эндпоинты
- `./internal/lib` - код, который можно переиспользовать в других проектах (здесь подключение к базе данных и функции для работы с `jwt`)
- `./internal/service` - сервисная логика
- `./internal/store` - логика для работы с бд и блэклистом