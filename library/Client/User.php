<?php
declare(strict_types=1);
namespace Coinsnap\Client;

class User extends AbstractClient
{
    public function getCurrentUserInformation(): \Coinsnap\Result\User
    {
        $url = $this->getApiUrl() . 'users/me';
        $headers = $this->getRequestHeaders();
        $method = 'GET';
        $response = $this->getHttpClient()->request($method, $url, $headers);

        if ($response->getStatus() === 200) {
            return new \Coinsnap\Result\User(
                json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR)
            );
        } else {
            throw $this->getExceptionByStatusCode($method, $url, $response);
        }
    }

    public function deleteCurrentUserProfile(): bool
    {
        $url = $this->getApiUrl() . 'users/me';
        $headers = $this->getRequestHeaders();
        $method = 'DELETE';
        $response = $this->getHttpClient()->request($method, $url, $headers);

        if ($response->getStatus() === 200) {
            return true;
        } else {
            throw $this->getExceptionByStatusCode($method, $url, (int)$response->getStatus(), $response->getBody());
        }
    }

    public function createUser(
        string $email,
        string $password,
        ?bool $isAdministrator = false
    ): \Coinsnap\Result\User {
        $url = $this->getApiUrl() . 'users';

        $headers = $this->getRequestHeaders();
        $method = 'POST';

        $body = json_encode(
            [
                'email' => $email,
                'password' => $password,
                'isAdministrator' => $isAdministrator
            ],
            JSON_THROW_ON_ERROR
        );

        $response = $this->getHttpClient()->request($method, $url, $headers, $body);

        if ($response->getStatus() === 200) {
            return new \Coinsnap\Result\User(
                json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR)
            );
        } else {
            throw $this->getExceptionByStatusCode($method, $url, (int)$response->getStatus(), $response->getBody());
        }
    }

    public function deleteUser(string $userId): bool
    {
        $url = $this->getApiUrl() . 'users/' . urlencode($userId);
        $headers = $this->getRequestHeaders();
        $method = 'DELETE';
        $response = $this->getHttpClient()->request($method, $url, $headers);

        if ($response->getStatus() === 200) {
            return true;
        } else {
            throw $this->getExceptionByStatusCode($method, $url, (int)$response->getStatus(), $response->getBody());
        }
    }
}
