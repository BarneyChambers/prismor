"""Typosquatting detection: edit distance against each registry's most-used names.

The lists below are the most-downloaded / most-depended-on packages per
registry (npm, PyPI, crates.io, Go modules, RubyGems, Packagist, Maven
Central), compiled offline -- no network at check time. A name that is *on*
a list is never flagged, so popular packages that happen to sit one edit apart
(``chai``/``chalk``, ``pypdf``/``pypdf2``) protect each other.

False-positive controls (the signal is +40, a warn on its own):

* Targets shorter than 5 characters are never matched: ``vue``, ``six``,
  ``pg``, ``gin`` each have dozens of legitimate one-edit neighbours.
* Distance 1 for targets up to 10 characters, 2 for longer ones, and the
  lengths may differ by at most 2.
* PyPI names are compared after PEP 503 normalisation, so ``python_dateutil``
  *is* ``python-dateutil``; npm has no such rule, so ``crossenv`` is a squat
  of ``cross-env`` (it was, in 2017).
* Namespaced registries (Go module paths, Packagist ``vendor/pkg``, Maven
  ``group:artifact``) are only matched across a *different* owner: a sibling
  inside ``golang.org/x/`` or ``symfony/`` is published by the same owner and
  cannot be a squat.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

# ── Popular-package lists (one per registry) ────────────────────────────

_NPM: Tuple[str, ...] = (
    # frameworks / UI
    "react", "react-dom", "react-native", "react-router", "react-router-dom",
    "react-redux", "react-is", "react-query", "react-hook-form", "react-scripts",
    "next", "nuxt", "vue", "vuex", "vue-router", "pinia", "angular", "svelte",
    "solid-js", "preact", "lit", "jquery", "bootstrap", "antd", "gatsby", "remix",
    "astro", "electron", "expo", "three", "d3", "chart.js", "framer-motion",
    "styled-components", "classnames", "clsx", "prop-types", "redux",
    "redux-thunk", "redux-saga", "reselect", "immer", "zustand", "mobx", "swr",
    "formik", "scheduler", "hoist-non-react-statics", "tailwindcss",
    "tailwind-merge", "postcss", "autoprefixer", "sass", "less", "stylus",
    # build / tooling
    "typescript", "webpack", "webpack-cli", "webpack-dev-server", "vite",
    "rollup", "esbuild", "parcel", "turbo", "nx", "lerna", "babel-core",
    "babel-loader", "babel-preset-env", "css-loader", "style-loader",
    "file-loader", "url-loader", "sass-loader", "postcss-loader",
    "html-webpack-plugin", "mini-css-extract-plugin", "terser", "uglify-js",
    "eslint", "eslint-config-prettier", "eslint-plugin-react",
    "eslint-plugin-import", "eslint-plugin-prettier", "typescript-eslint",
    "prettier", "husky", "lint-staged", "nodemon", "concurrently", "ts-node",
    "tsx", "ts-jest", "tslib", "core-js", "regenerator-runtime", "browserify",
    "gulp", "grunt", "bower", "yarn", "pnpm", "npm", "npx", "storybook",
    "patch-package", "cross-env", "rimraf", "mkdirp", "dotenv", "dotenv-expand",
    # testing
    "jest", "vitest", "mocha", "chai", "sinon", "jasmine", "karma", "cypress",
    "playwright", "puppeteer", "supertest", "nock", "enzyme", "ava", "tap",
    # server / http
    "express", "koa", "fastify", "hapi", "body-parser", "cookie-parser",
    "cors", "helmet", "morgan", "multer", "passport", "express-session",
    "express-validator", "compression", "serve-static", "http-proxy",
    "http-proxy-middleware", "http-errors", "socket.io", "socket.io-client",
    "ws", "axios", "node-fetch", "cross-fetch", "isomorphic-fetch", "request",
    "superagent", "got", "undici", "form-data", "cheerio", "jsdom",
    "graphql", "graphql-tag", "apollo-server", "apollo-client", "urql",
    "nodemailer", "jsonwebtoken", "bcrypt", "bcryptjs", "uuid", "nanoid",
    "cookie", "qs", "query-string", "path-to-regexp", "mime", "mime-types",
    # data / db
    "mongoose", "mongodb", "mysql", "mysql2", "pg", "sqlite3", "sequelize",
    "typeorm", "prisma", "knex", "drizzle-orm", "redis", "ioredis", "kafkajs",
    "amqplib", "bull", "bullmq", "node-cron", "cron", "firebase", "aws-sdk",
    "stripe", "twilio", "openai", "langchain", "langfuse",
    # utilities
    "lodash", "lodash-es", "lodash.merge", "lodash.get", "underscore",
    "ramda", "immutable", "rxjs", "moment", "moment-timezone", "dayjs",
    "date-fns", "luxon", "chalk", "colors", "kleur", "picocolors", "debug",
    "commander", "yargs", "minimist", "meow", "inquirer", "prompts", "ora",
    "boxen", "figlet", "cli-table3", "progress", "chokidar", "glob",
    "minimatch", "micromatch", "fast-glob", "globby", "semver", "fs-extra",
    "graceful-fs", "execa", "shelljs", "cross-spawn", "which", "open",
    "zod", "yup", "joi", "ajv", "validator", "class-validator",
    "class-transformer", "reflect-metadata", "winston", "pino", "bunyan",
    "log4js", "marked", "markdown-it", "highlight.js", "handlebars", "ejs",
    "pug", "mustache", "nunjucks", "yaml", "js-yaml", "xml2js",
    "fast-xml-parser", "papaparse", "csv-parse", "xlsx", "sharp", "jimp",
    "canvas", "pdfkit", "protobufjs", "bluebird", "async", "deepmerge",
    "object-assign", "extend", "inherits", "safe-buffer", "buffer", "events",
    "util", "readable-stream", "through2", "iconv-lite", "tough-cookie",
    "invariant", "warning", "loose-envify", "js-tokens", "source-map",
    "source-map-support", "acorn", "esprima", "estraverse", "ansi-regex",
    "ansi-styles", "strip-ansi", "supports-color", "string-width",
    "wrap-ansi", "escape-string-regexp", "punycode", "whatwg-url", "ms",
    "eventemitter3", "uuidv4", "big.js", "bignumber.js", "decimal.js",
    "crypto-js", "jszip", "archiver", "tar", "adm-zip", "node-gyp",
    "electron-builder", "config", "convict", "nconf", "lru-cache",
    "node-cache", "p-limit", "p-queue", "fuse.js", "socks-proxy-agent",
    "https-proxy-agent", "http-proxy-agent", "web-vitals", "three-stdlib",
    "bowser", "stylis", "safer-buffer", "object.assign",
)

_PYPI: Tuple[str, ...] = (
    # packaging / core
    "pip", "setuptools", "wheel", "packaging", "six", "certifi", "idna",
    "urllib3", "requests", "charset-normalizer", "chardet", "python-dateutil",
    "pytz", "tzdata", "tzlocal", "pyyaml", "typing-extensions",
    "typing-inspect", "mypy-extensions", "attrs", "cattrs", "filelock",
    "platformdirs", "distlib", "virtualenv", "pipenv", "poetry", "poetry-core",
    "hatchling", "flit-core", "setuptools-scm", "build", "twine", "tomli",
    "tomlkit", "toml", "importlib-metadata", "importlib-resources", "zipp",
    "wrapt", "decorator", "more-itertools", "pyparsing", "jsonschema",
    "jsonschema-specifications", "referencing", "rpds-py", "cffi",
    "pycparser", "markupsafe", "jinja2", "click", "colorama", "tqdm", "rich",
    "typer", "termcolor", "tabulate", "prettytable", "humanize", "psutil",
    "pexpect", "ptyprocess", "python-dotenv", "environs", "regex", "simplejson",
    "ujson", "orjson", "msgpack", "protobuf", "grpcio", "grpcio-tools",
    "grpcio-status", "googleapis-common-protos", "deprecated", "jmespath",
    "pyrsistent", "isodate", "defusedxml", "xmltodict", "lxml",
    "beautifulsoup4", "bs4", "soupsieve", "html5lib", "cachetools",
    "tenacity", "backoff", "retrying", "structlog", "loguru", "colorlog",
    "arrow", "pendulum", "babel", "sqlparse",
    # web
    "flask", "django", "fastapi", "starlette", "uvicorn", "gunicorn",
    "werkzeug", "itsdangerous", "tornado", "aiohttp", "httpx", "httpcore",
    "h11", "anyio", "sniffio", "trio", "websockets", "websocket-client",
    "requests-oauthlib", "oauthlib", "requests-toolbelt", "python-multipart",
    "email-validator", "dnspython", "flask-sqlalchemy", "flask-cors",
    "flask-login", "flask-wtf", "wtforms", "djangorestframework",
    "django-cors-headers", "channels", "whitenoise", "dj-database-url",
    "pydantic", "pydantic-core", "pydantic-settings", "marshmallow",
    "dataclasses-json", "scrapy", "selenium", "playwright",
    # security / crypto
    "cryptography", "pyopenssl", "pyjwt", "bcrypt", "passlib", "paramiko",
    "pynacl", "asn1crypto", "rsa", "pyasn1", "pyasn1-modules", "pycryptodome",
    "pycryptodomex", "keyring", "jeepney", "secretstorage",
    # data / science / ml
    "numpy", "pandas", "scipy", "matplotlib", "seaborn", "scikit-learn",
    "sklearn", "scikit-image", "statsmodels", "sympy", "networkx", "numba",
    "llvmlite", "pyarrow", "polars", "dask", "xgboost", "lightgbm", "catboost",
    "plotly", "bokeh", "dash", "streamlit", "gradio", "tensorflow", "keras",
    "torch", "torchvision", "torchaudio", "transformers", "datasets",
    "tokenizers", "huggingface-hub", "accelerate", "safetensors",
    "sentencepiece", "sentence-transformers", "nltk", "spacy", "gensim",
    "opencv-python", "opencv-python-headless", "pillow", "imageio", "shapely",
    "geopandas", "pyproj", "folium", "openpyxl", "xlrd", "xlsxwriter",
    "python-docx", "pypdf", "pypdf2", "reportlab", "markdown", "mistune",
    "docutils", "sphinx", "pygments", "jupyter", "jupyterlab", "notebook",
    "ipython", "ipykernel", "ipywidgets", "nbformat", "nbconvert", "traitlets",
    "pyzmq", "jedi", "parso", "prompt-toolkit", "wcwidth", "faiss-cpu",
    "chromadb", "pinecone-client", "tiktoken",
    # llm / agents
    "openai", "anthropic", "langchain", "langchain-core", "langchain-community",
    "langchain-openai", "langgraph", "llama-index", "litellm", "cohere",
    "mistralai", "google-generativeai", "langfuse", "haystack-ai", "dspy",
    "mirascope", "instructor", "ollama", "smolagents", "crewai", "pyautogen",
    "autogen", "langflow", "promptfoo",
    # cloud / infra
    "boto3", "botocore", "s3transfer", "awscli", "aiobotocore", "s3fs",
    "fsspec", "boto", "google-cloud-storage", "google-api-core", "google-auth",
    "google-api-python-client", "azure-core", "azure-storage-blob",
    "azure-identity", "docker", "kubernetes", "ansible", "fabric", "invoke",
    "sentry-sdk", "prometheus-client", "opentelemetry-api",
    "opentelemetry-sdk", "elasticsearch", "pika", "confluent-kafka",
    "kafka-python", "slack-sdk", "stripe", "twilio", "tweepy",
    # db
    "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary", "psycopg",
    "pymysql", "mysqlclient", "pymongo", "redis", "celery", "kombu",
    "billiard", "amqp", "vine", "pyodbc", "oracledb", "cx-oracle",
    # testing / quality
    "pytest", "pytest-cov", "pytest-mock", "pytest-asyncio", "pytest-xdist",
    "coverage", "tox", "nox", "mock", "hypothesis", "faker", "factory-boy",
    "black", "isort", "flake8", "pylint", "mypy", "ruff", "autopep8", "yapf",
    "pycodestyle", "pyflakes", "mccabe", "bandit", "pre-commit",
    # misc
    "cython", "pybind11", "greenlet", "gevent", "eventlet", "uvloop",
    "pyinstaller", "pygame", "kivy", "pyqt5", "pyside6", "wxpython",
    "pyserial", "pyusb", "pywin32", "sh", "tomli-w", "authlib",
)

_CRATES: Tuple[str, ...] = (
    "serde", "serde_json", "serde_derive", "serde_yaml", "serde_with",
    "tokio", "tokio-util", "tokio-stream", "tokio-rustls", "tokio-tungstenite",
    "hyper", "hyper-util", "hyper-tls", "reqwest", "ureq", "curl", "http",
    "http-body", "httparse", "h2", "tower", "tower-http", "axum", "actix-web",
    "actix-rt", "warp", "rocket", "tide", "async-std", "smol", "mio",
    "futures", "futures-util", "async-trait", "pin-project",
    "pin-project-lite", "bytes", "clap", "structopt", "anyhow", "thiserror",
    "eyre", "color-eyre", "miette", "tracing", "tracing-subscriber",
    "tracing-appender", "log", "env_logger", "rand", "rand_core", "getrandom",
    "regex", "lazy_static", "once_cell", "chrono", "time", "humantime",
    "itertools", "syn", "quote", "proc-macro2", "libc", "cfg-if", "bitflags",
    "base64", "hex", "sha2", "sha1", "sha3", "md-5", "digest", "hmac", "ring",
    "rustls", "rustls-pemfile", "webpki-roots", "native-tls", "openssl",
    "openssl-sys", "uuid", "url", "percent-encoding", "form_urlencoded",
    "idna", "mime", "mime_guess", "parking_lot", "crossbeam",
    "crossbeam-channel", "rayon", "num", "num-traits", "num-bigint",
    "smallvec", "indexmap", "hashbrown", "ahash", "dashmap", "arc-swap",
    "slab", "memchr", "byteorder", "flate2", "zip", "tar", "walkdir", "glob",
    "tempfile", "dirs", "directories", "toml", "csv", "bincode", "prost",
    "tonic", "diesel", "sqlx", "rusqlite", "redis", "mongodb", "sea-orm",
    "strum", "strum_macros", "derive_more", "colored", "termcolor",
    "indicatif", "console", "dialoguer", "crossterm", "ratatui", "tui", "nom",
    "pest", "unicode-width", "unicode-segmentation", "semver", "nix",
    "winapi", "windows", "windows-sys", "jemallocator", "mimalloc",
    "criterion", "proptest", "quickcheck", "insta", "mockall",
    "wasm-bindgen", "js-sys", "web-sys", "image", "bevy", "egui", "wgpu",
    "winit", "socket2", "tungstenite", "lettre", "handlebars", "tera",
    "askama", "minijinja", "git2", "pkg-config", "cc", "cmake", "bindgen",
    "libloading", "which", "shellexpand", "fs_extra", "notify", "heck",
    "convert_case", "paste", "typenum", "generic-array", "subtle", "zeroize",
    "aes", "aes-gcm", "chacha20poly1305", "ed25519-dalek", "curve25519-dalek",
    "x25519-dalek", "blake3", "argon2", "bcrypt", "jsonwebtoken", "validator",
    "config", "dotenv", "dotenvy", "figment", "sentry", "metrics",
    "prometheus", "opentelemetry", "backtrace", "either", "scopeguard",
    "static_assertions", "memmap2", "encoding_rs", "serde_bytes", "rmp-serde",
    "ciborium", "postcard", "chrono-tz", "cargo_metadata", "camino",
)

_GO: Tuple[str, ...] = (
    "github.com/gin-gonic/gin", "github.com/labstack/echo",
    "github.com/gofiber/fiber", "github.com/go-chi/chi",
    "github.com/gorilla/mux", "github.com/gorilla/websocket",
    "github.com/gorilla/sessions", "github.com/gorilla/handlers",
    "github.com/julienschmidt/httprouter", "github.com/valyala/fasthttp",
    "github.com/rs/cors", "gorm.io/gorm", "gorm.io/driver/postgres",
    "gorm.io/driver/mysql", "gorm.io/driver/sqlite", "github.com/jinzhu/gorm",
    "github.com/stretchr/testify", "github.com/stretchr/objx",
    "github.com/davecgh/go-spew", "github.com/pmezard/go-difflib",
    "github.com/sirupsen/logrus", "go.uber.org/zap", "github.com/rs/zerolog",
    "github.com/go-logr/logr", "k8s.io/klog", "github.com/golang/glog",
    "github.com/spf13/cobra", "github.com/spf13/viper", "github.com/spf13/pflag",
    "github.com/spf13/afero", "github.com/spf13/cast", "github.com/urfave/cli",
    "github.com/google/uuid", "github.com/gofrs/uuid", "github.com/satori/go.uuid",
    "github.com/pkg/errors", "github.com/hashicorp/go-multierror",
    "github.com/golang/protobuf", "google.golang.org/protobuf",
    "google.golang.org/grpc", "github.com/grpc-ecosystem/grpc-gateway",
    "github.com/golang-jwt/jwt", "github.com/dgrijalva/jwt-go",
    "github.com/go-redis/redis", "github.com/redis/go-redis",
    "github.com/lib/pq", "github.com/jackc/pgx", "github.com/go-sql-driver/mysql",
    "github.com/mattn/go-sqlite3", "github.com/jmoiron/sqlx",
    "go.mongodb.org/mongo-driver", "github.com/aws/aws-sdk-go",
    "github.com/aws/aws-sdk-go-v2", "cloud.google.com/go",
    "github.com/Azure/azure-sdk-for-go", "github.com/prometheus/client_golang",
    "go.opentelemetry.io/otel", "github.com/hashicorp/terraform",
    "github.com/hashicorp/consul", "github.com/hashicorp/vault",
    "github.com/hashicorp/hcl", "github.com/hashicorp/go-retryablehttp",
    "github.com/hashicorp/golang-lru", "github.com/hashicorp/go-version",
    "k8s.io/client-go", "k8s.io/api", "k8s.io/apimachinery",
    "sigs.k8s.io/controller-runtime", "sigs.k8s.io/yaml",
    "github.com/docker/docker", "github.com/containerd/containerd",
    "github.com/opencontainers/runc", "github.com/opencontainers/image-spec",
    "github.com/google/go-containerregistry", "github.com/BurntSushi/toml",
    "github.com/pelletier/go-toml", "gopkg.in/yaml.v2", "gopkg.in/yaml.v3",
    "github.com/go-yaml/yaml", "github.com/json-iterator/go",
    "github.com/tidwall/gjson", "github.com/go-playground/validator",
    "github.com/go-resty/resty", "github.com/joho/godotenv",
    "github.com/kelseyhightower/envconfig", "github.com/fsnotify/fsnotify",
    "github.com/robfig/cron", "github.com/nats-io/nats.go",
    "github.com/segmentio/kafka-go", "github.com/Shopify/sarama",
    "github.com/IBM/sarama", "github.com/streadway/amqp",
    "github.com/rabbitmq/amqp091-go", "github.com/olekukonko/tablewriter",
    "github.com/fatih/color", "github.com/charmbracelet/bubbletea",
    "github.com/charmbracelet/lipgloss", "github.com/mitchellh/mapstructure",
    "github.com/mitchellh/go-homedir", "github.com/golang/mock",
    "go.uber.org/mock", "github.com/onsi/ginkgo", "github.com/onsi/gomega",
    "github.com/google/go-cmp", "github.com/google/wire", "go.uber.org/fx",
    "go.uber.org/dig", "github.com/swaggo/swag", "github.com/swaggo/gin-swagger",
    "github.com/99designs/gqlgen", "github.com/graphql-go/graphql",
    "github.com/boltdb/bolt", "go.etcd.io/bbolt", "go.etcd.io/etcd",
    "github.com/dgraph-io/badger", "github.com/syndtr/goleveldb",
    "github.com/patrickmn/go-cache", "github.com/allegro/bigcache",
    "github.com/golang/groupcache", "golang.org/x/net", "golang.org/x/crypto",
    "golang.org/x/sys", "golang.org/x/text", "golang.org/x/oauth2",
    "golang.org/x/sync", "golang.org/x/time", "golang.org/x/tools",
    "golang.org/x/exp", "golang.org/x/mod", "golang.org/x/term",
    "github.com/cespare/xxhash", "github.com/klauspost/compress",
    "github.com/golang/snappy", "github.com/pierrec/lz4",
    "github.com/shopspring/decimal", "github.com/go-kit/kit",
    "github.com/micro/go-micro", "github.com/minio/minio-go",
    "github.com/cenkalti/backoff", "github.com/avast/retry-go",
    "github.com/PuerkitoBio/goquery", "github.com/gocolly/colly",
    "github.com/chromedp/chromedp", "github.com/sashabaranov/go-openai",
    "github.com/tmc/langchaingo", "github.com/ethereum/go-ethereum",
    "github.com/btcsuite/btcd", "github.com/google/go-github",
    "github.com/xanzy/go-gitlab", "github.com/go-git/go-git",
    "github.com/schollz/progressbar", "github.com/manifoldco/promptui",
    "github.com/AlecAivazis/survey", "github.com/jedib0t/go-pretty",
    "github.com/magiconair/properties", "github.com/Masterminds/semver",
    "github.com/Masterminds/sprig", "github.com/sergi/go-diff",
    "github.com/yuin/goldmark", "github.com/microcosm-cc/bluemonday",
    "github.com/disintegration/imaging",
)

_RUBYGEMS: Tuple[str, ...] = (
    "rails", "rake", "bundler", "rack", "rack-test", "rspec", "rspec-core",
    "rspec-rails", "rspec-mocks", "rspec-expectations", "rubocop", "puma",
    "unicorn", "passenger", "thin", "nokogiri", "devise", "devise_invitable",
    "sidekiq", "resque", "pg", "mysql2", "sqlite3", "redis", "activerecord",
    "activesupport", "activemodel", "actionpack", "actionview", "railties",
    "thor", "json", "minitest", "capybara", "factory_bot", "factory_bot_rails",
    "faker", "pry", "pry-byebug", "byebug", "sinatra", "jbuilder", "sass-rails",
    "webpacker", "turbo-rails", "stimulus-rails", "importmap-rails",
    "bootsnap", "listen", "spring", "web-console", "selenium-webdriver",
    "webdrivers", "rest-client", "httparty", "faraday", "aws-sdk",
    "aws-sdk-s3", "aws-sdk-core", "fog-aws", "carrierwave", "paperclip",
    "kaminari", "will_paginate", "pundit", "cancancan", "omniauth", "jwt",
    "bcrypt", "dotenv", "dotenv-rails", "figaro", "rubyzip", "mini_magick",
    "image_processing", "simplecov", "webmock", "vcr", "shoulda-matchers",
    "database_cleaner", "guard", "tzinfo", "i18n", "concurrent-ruby",
    "mime-types", "nio4r", "websocket-driver", "ffi", "rainbow", "colorize",
    "tty-prompt", "highline", "addressable", "public_suffix", "builder",
    "erubi", "loofah", "rails-html-sanitizer", "mail", "net-smtp", "sprockets",
    "sprockets-rails", "coffee-rails", "uglifier", "jquery-rails", "haml",
    "slim", "graphql", "grape", "active_model_serializers", "sentry-ruby",
    "newrelic_rpm", "whenever", "chronic", "friendly_id", "paper_trail",
    "ransack", "draper", "rolify", "doorkeeper", "oj", "multi_json",
    "yajl-ruby", "msgpack", "google-protobuf", "grpc", "octokit", "stripe",
    "twilio-ruby", "rest-client", "excon", "typhoeus", "ethon", "rexml",
    "zeitwerk", "rouge", "kramdown", "redcarpet", "jekyll", "cocoapods",
    "fastlane", "rubygems-update", "racc", "psych", "date", "mysql",
)

_PACKAGIST: Tuple[str, ...] = (
    "laravel/framework", "laravel/laravel", "laravel/sanctum",
    "laravel/passport", "laravel/tinker", "laravel/sail", "laravel/horizon",
    "laravel/socialite", "symfony/symfony", "symfony/console",
    "symfony/http-foundation", "symfony/http-kernel", "symfony/routing",
    "symfony/yaml", "symfony/process", "symfony/finder",
    "symfony/event-dispatcher", "symfony/var-dumper",
    "symfony/polyfill-mbstring", "symfony/polyfill-ctype", "symfony/mailer",
    "symfony/translation", "symfony/dotenv", "guzzlehttp/guzzle",
    "guzzlehttp/psr7", "guzzlehttp/promises", "monolog/monolog",
    "phpunit/phpunit", "doctrine/orm", "doctrine/dbal", "doctrine/annotations",
    "doctrine/inflector", "doctrine/lexer", "psr/log", "psr/http-message",
    "psr/container", "psr/simple-cache", "nesbot/carbon", "vlucas/phpdotenv",
    "league/flysystem", "league/oauth2-client", "league/commonmark",
    "ramsey/uuid", "fakerphp/faker", "fzaninotto/faker", "mockery/mockery",
    "phpstan/phpstan", "squizlabs/php_codesniffer",
    "friendsofphp/php-cs-fixer", "composer/composer", "aws/aws-sdk-php",
    "google/apiclient", "firebase/php-jwt", "tymon/jwt-auth",
    "spatie/laravel-permission", "barryvdh/laravel-debugbar",
    "barryvdh/laravel-dompdf", "dompdf/dompdf", "phpmailer/phpmailer",
    "swiftmailer/swiftmailer", "twig/twig", "slim/slim", "predis/predis",
    "intervention/image", "maatwebsite/excel", "phpoffice/phpspreadsheet",
    "nikic/php-parser", "sebastian/diff", "egulias/email-validator",
    "filp/whoops", "nunomaduro/collision", "paragonie/random_compat",
    "defuse/php-encryption", "stripe/stripe-php", "cakephp/cakephp",
    "yiisoft/yii2", "drupal/core", "wp-cli/wp-cli", "livewire/livewire",
    "inertiajs/inertia-laravel", "pestphp/pest", "vimeo/psalm", "rector/rector",
)

_MAVEN: Tuple[str, ...] = (
    "org.springframework.boot:spring-boot-starter",
    "org.springframework.boot:spring-boot-starter-web",
    "org.springframework.boot:spring-boot-starter-test",
    "org.springframework.boot:spring-boot-starter-data-jpa",
    "org.springframework:spring-core", "org.springframework:spring-context",
    "org.springframework:spring-web", "org.springframework:spring-webmvc",
    "com.fasterxml.jackson.core:jackson-databind",
    "com.fasterxml.jackson.core:jackson-core",
    "com.fasterxml.jackson.core:jackson-annotations",
    "com.google.guava:guava", "com.google.code.gson:gson",
    "org.apache.commons:commons-lang3", "org.apache.commons:commons-collections4",
    "commons-io:commons-io", "commons-codec:commons-codec",
    "org.apache.httpcomponents:httpclient",
    "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-api",
    "org.slf4j:slf4j-api", "ch.qos.logback:logback-classic", "junit:junit",
    "org.junit.jupiter:junit-jupiter", "org.junit.jupiter:junit-jupiter-api",
    "org.mockito:mockito-core", "org.assertj:assertj-core",
    "org.projectlombok:lombok", "org.hibernate:hibernate-core",
    "org.hibernate.orm:hibernate-core", "mysql:mysql-connector-java",
    "com.mysql:mysql-connector-j", "org.postgresql:postgresql",
    "com.h2database:h2", "com.squareup.okhttp3:okhttp",
    "com.squareup.retrofit2:retrofit", "io.netty:netty-all",
    "io.reactivex.rxjava3:rxjava", "org.jetbrains.kotlin:kotlin-stdlib",
    "org.jetbrains.kotlinx:kotlinx-coroutines-core",
    "org.apache.kafka:kafka-clients", "software.amazon.awssdk:s3",
    "com.amazonaws:aws-java-sdk-s3", "io.grpc:grpc-netty",
    "com.google.protobuf:protobuf-java", "org.yaml:snakeyaml",
    "io.jsonwebtoken:jjwt", "org.testng:testng", "io.micrometer:micrometer-core",
    "org.apache.poi:poi", "org.bouncycastle:bcprov-jdk18on",
    "org.springdoc:springdoc-openapi-ui", "redis.clients:jedis",
    "io.lettuce:lettuce-core", "org.mongodb:mongodb-driver-sync",
    "com.zaxxer:hikaricp", "org.flywaydb:flyway-core",
    "org.liquibase:liquibase-core", "org.apache.tomcat.embed:tomcat-embed-core",
    "javax.servlet:javax.servlet-api", "jakarta.servlet:jakarta.servlet-api",
)

# Registry → list, then every internal ecosystem label onto its registry.
_REGISTRY_LISTS: Dict[str, Tuple[str, ...]] = {
    "npm": _NPM, "pypi": _PYPI, "crates": _CRATES, "go": _GO,
    "rubygems": _RUBYGEMS, "packagist": _PACKAGIST, "maven": _MAVEN,
}
ECOSYSTEM_REGISTRY: Dict[str, str] = {
    "npm": "npm", "pnpm": "npm", "yarn": "npm", "bun": "npm",
    "pypi": "pypi", "pip": "pypi", "pip3": "pypi", "uv": "pypi", "poetry": "pypi",
    "cargo": "crates", "crates": "crates", "crates.io": "crates",
    "go": "go",
    "gem": "rubygems", "bundle": "rubygems", "rubygems": "rubygems",
    "composer": "packagist", "packagist": "packagist",
    "maven": "maven", "gradle": "maven",
}

# Kept for callers that read the lists directly (ecosystem label → names).
POPULAR_PACKAGES: Dict[str, List[str]] = {
    eco: list(_REGISTRY_LISTS[reg]) for eco, reg in ECOSYSTEM_REGISTRY.items()
}

# npm scopes owned by well-known publishers. A scope is registry-verified, so
# ``@radix-ui/react-id`` is Radix's package, not a squat of ``react-is``.
TRUSTED_NPM_SCOPES: FrozenSet[str] = frozenset({
    "types", "babel", "angular", "vue", "nestjs", "aws-sdk", "smithy",
    "google-cloud", "azure", "mui", "emotion", "radix-ui", "testing-library",
    "typescript-eslint", "eslint", "storybook", "reduxjs", "tanstack", "apollo",
    "prisma", "next", "vercel", "sentry", "octokit", "anthropic-ai", "openai",
    "langchain", "rollup", "esbuild", "swc", "jest", "vitest", "playwright",
    "nuxt", "firebase", "grpc", "fortawesome", "headlessui", "heroicons",
    "floating-ui", "react-native", "expo", "supabase", "trpc", "nrwl", "nx",
    "parcel", "vitejs", "sveltejs", "remix-run", "astrojs", "graphql-tools",
    "opentelemetry", "webassemblyjs", "jridgewell", "commitlint", "changesets",
    "biomejs", "modelcontextprotocol", "clerk", "stripe", "microsoft",
})

# Separator between owner and package in namespaced registries.
_NAMESPACE_SEP = {"go": "/", "packagist": "/", "maven": ":"}

_MIN_TARGET_LEN = 5      # shorter targets have too many legitimate neighbours
_MIN_CANDIDATE_LEN = 4
_GO_MAJOR_SUFFIX = re.compile(r"/v\d+$")
_JS_SUFFIX = re.compile(r"\.js$")


def _edit_distance(a: str, b: str) -> int:
    """Edit distance between a and b, counting a swap of two neighbours as one.

    Plain Levenshtein scores a swapped pair as two edits, so ``reqeusts``
    sat at distance 2 from ``requests`` and slipped under the distance-1
    threshold for short names (#555). A swap is one keystroke slip, the
    commonest typo there is, so it costs one edit here (optimal string
    alignment distance).
    """
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev2: List[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (ca != cb)
            cost = min(insertions, deletions, substitutions)
            if i and j and ca == b[j - 1] and a[i - 1] == cb:
                cost = min(cost, prev2[j - 1] + 1)
            curr.append(cost)
        prev2, prev = prev, curr
    return prev[-1]


def _bounded_distance(a: str, b: str, limit: int) -> int:
    """``_edit_distance`` that gives up once it must exceed ``limit``.

    Returns the exact distance when it is <= limit, otherwise limit + 1.
    Hundreds of comparisons run per install command on the hook path, and
    nearly all of them are hopeless after the first few characters.
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: List[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb))
            if i and j and ca == b[j - 1] and a[i - 1] == cb:
                cost = min(cost, prev2[j - 1] + 1)
            curr.append(cost)
        if min(curr) > limit:
            # OSA can reach back two rows via a transposition, but that path
            # costs at least min(prev) + 1 -- so both rows over budget is final.
            if min(prev) > limit:
                return limit + 1
        prev2, prev = prev, curr
    return min(prev[-1], limit + 1)


def _canonical(name: str, registry: str) -> str:
    """The registry's own notion of "the same name"."""
    name = name.strip().lower()
    if registry == "pypi":
        return re.sub(r"[-_.]+", "-", name)          # PEP 503
    if registry == "go":
        return _GO_MAJOR_SUFFIX.sub("", name.split("@", 1)[0])
    if registry == "crates":
        return name.replace("-", "_")                # crates.io: - and _ are one name
    if registry == "maven":
        return ":".join(name.split(":")[:2])         # drop :version
    return name


def _squash(name: str, registry: str) -> str:
    """Separator-insensitive form used for the distance itself."""
    if registry in _NAMESPACE_SEP:
        return name  # paths: separators carry meaning
    return re.sub(r"[-_.]", "", name)


def _split_owner(name: str, registry: str) -> Tuple[str, str]:
    sep = _NAMESPACE_SEP.get(registry)
    if not sep or sep not in name:
        return "", name
    owner, _, leaf = name.rpartition(sep)
    return owner, leaf


@lru_cache(maxsize=None)
def _targets(registry: str) -> Tuple[FrozenSet[str], Tuple[Tuple[str, str, str, str], ...]]:
    """(canonical names, [(original, squashed, owner, leaf)]) for a registry."""
    names: Sequence[str] = _REGISTRY_LISTS.get(registry, ())
    canon = frozenset(_canonical(n, registry) for n in names)
    rows = []
    for n in names:
        c = _canonical(n, registry)
        owner, leaf = _split_owner(c, registry)
        rows.append((n, _squash(c, registry), owner, leaf))
    return canon, tuple(rows)


def check_typosquat(package_name: str, ecosystem: str) -> Optional[str]:
    """Check if package_name is a typosquat of a popular package.

    Returns the trusted package name being mimicked, or None.
    Strips npm @scope/ prefix for comparison.
    """
    registry = ECOSYSTEM_REGISTRY.get(ecosystem.lower())
    if registry is None:
        return None

    name = package_name.strip().lower()
    if registry == "npm":
        # Strip scope (@scope/pkg -> pkg; a bare "@pkg" -> pkg)
        if name.startswith("@") and "/" in name:
            scope, name = name[1:].split("/", 1)
            if scope in TRUSTED_NPM_SCOPES:
                return None
        elif name.startswith("@"):
            name = name[1:]

    canon_set, rows = _targets(registry)
    name = _canonical(name, registry)
    if not name or name in canon_set:
        return None

    if registry == "npm":
        # "<popular>.js" (cross-env.js, jquery.js, 2017). Not "-js": postcss-js
        # and source-map-js are real packages.
        bare = _JS_SUFFIX.sub("", name)
        if bare != name and len(bare) >= _MIN_CANDIDATE_LEN and bare in canon_set:
            return next(n for n in _REGISTRY_LISTS[registry] if n == bare)

    squashed = _squash(name, registry)
    if len(squashed) < _MIN_CANDIDATE_LEN:
        return None
    owner, leaf = _split_owner(name, registry)
    namespaced = registry in _NAMESPACE_SEP

    best: Optional[Tuple[int, str]] = None
    for original, t_squashed, t_owner, t_leaf in rows:
        if len(t_squashed) < _MIN_TARGET_LEN:
            continue
        if abs(len(squashed) - len(t_squashed)) > 3:
            continue
        threshold = 1 if len(t_squashed) <= 10 else 2
        if namespaced:
            if owner == t_owner:
                continue  # same publisher: a sibling, not a squat
            if leaf == t_leaf:
                threshold += 1  # owner-only squat: github.com/boltdb-go/bolt
        elif abs(len(squashed) - len(t_squashed)) > 2:
            continue
        if abs(len(squashed) - len(t_squashed)) > threshold:
            continue  # the length gap alone exceeds the budget
        distance = _bounded_distance(squashed, t_squashed, threshold)
        if distance <= threshold and (best is None or distance < best[0]):
            best = (distance, original)
            if distance == 0:
                break
    return best[1] if best else None
