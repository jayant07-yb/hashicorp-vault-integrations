package ysql

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"testing"

	"github.com/hashicorp/vault/helper/testhelpers/docker"
)

func PrepareTestContainer(t *testing.T, version string) (func(), string) {
	return prepareTestContainer(t, version, "secret", "database")
}

func PrepareTestContainerWithPassword(t *testing.T, version, password string) (func(), string) {
	return prepareTestContainer(t, version, password, "database")
}

func prepareTestContainer(t *testing.T, version, password, db string) (func(), string) {

	if version == "" {
		version = "latest"
	}

	runner, err := docker.NewServiceRunner(docker.RunOptions{
		ImageRepo:     "yugabytedb/yugabyte",
		Cmd:           []string{"./bin/yugabyted", "start", "--daemon=false"},
		ImageTag:      version,
		Env:           []string{"YSQL_DB=database", "YSQL_PASSWORD=" + password},
		Ports:         []string{"5433/tcp"},
		ContainerName: "yugabyte",
	})
	if err != nil {
		t.Fatalf("Could not start docker: %s", err)
	}

	svc, err := runner.StartService(context.Background(), connectYugabyte)
	if err != nil {
		t.Fatalf("Could not start docker: %s", err)
	}

	return svc.Cleanup, svc.Config.URL().String()
}

func connectYugabyte(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("yugabyte", "secret"),
		Host:     fmt.Sprintf("%s:%d", host, port),
		Path:     "postgres",
		RawQuery: "sslmode=disable",
	}

	db, err := sql.Open("postgres", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return docker.NewServiceURL(u), nil
}