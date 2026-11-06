# Практическая работа 14 — защищённые заметки

## Краткий отчёт

Сервис создаёт и показывает заметки после входа с JWT. Только администратор может удалять заметки.

## Выполнение по заданию

### 1. Пользователи и вход

При запуске создаются учебные пользователи `student` / `Student123!` и `admin` / `Admin123!`. Пароли в памяти хранятся в виде bcrypt-хешей. `POST /auth/login` возвращает токен на 30 минут.

### 2. Маршруты

`GET /notes` возвращает свои заметки пользователю и все администратору. `POST /notes` создаёт заметку с владельцем из токена. `DELETE /notes/{id}` доступен только администратору. Данные в памяти защищены `sync.RWMutex`.

### 3. Проверка

Проверены неверный пароль, отсутствие и подделка токена, просроченный токен, создание и просмотр заметки, запрет удаления пользователем и удаление администратором.

## Запуск

```powershell
$env:JWT_SECRET = "labs-demo-secret-change-it"
go run .
```

Секрет задаётся через переменную окружения. Тестовые учётные данные предназначены только для учебного примера.

## Пример проверки в PowerShell

Откройте второе окно PowerShell, пока сервер работает:

```powershell
$body = @{ username = "student"; password = "Student123!" } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri http://localhost:8080/auth/login -ContentType "application/json" -Body $body
$headers = @{ Authorization = "Bearer $($login.access_token)" }
```

Далее используйте `$headers` в защищённых запросах. Для администратора войдите с `admin` и `Admin123!`.

```powershell
$note = @{ title = "Первая заметка"; content = "Текст заметки" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8080/notes -Headers $headers -ContentType "application/json" -Body $note
Invoke-RestMethod -Uri http://localhost:8080/notes -Headers $headers
```

## Вывод

Middleware проверяет подпись, алгоритм и срок JWT. Роль определяет, разрешено ли удаление.
