package oauth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOauthConstans(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-Id", headerXClientID)
	assert.EqualValues(t, "X-Caller-Id", headerXCallerID)
	assert.EqualValues(t, "access_token", paramAccessToken)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil))
}

func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.False(t, IsPublic(&request))
	request.Header.Add("X-Public", "true")
	assert.True(t, IsPublic(&request))
}
