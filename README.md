# restream-api

General backend for restream app.

### Run generate schema

```
sqlc generate -f ./db/sqlc.yaml
```

### Run migrations with goose

>Example
```
goose -dir ./db/migrations postgres "host=localhost user=postgres dbname=postgres password=postgres
 sslmode=disable" up
```

### Provide env file from env.example folder

//TODO take these scripts into bash, make, json, or lua. Still researching