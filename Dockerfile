FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/claustra ./cmd/claustra

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/claustra /usr/local/bin/claustra
EXPOSE 13002
ENTRYPOINT ["/usr/local/bin/claustra"]
CMD ["serve"]
