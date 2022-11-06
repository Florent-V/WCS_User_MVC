<?php

namespace App\Model;

class UserManager extends AbstractManager
{
    public const TABLE = 'user';

    public function selectOneByEmail(string $email): array|false
    {
        $statement = $this->pdo->prepare("SELECT * FROM " . self::TABLE . " WHERE email=:email");
        $statement->bindValue('email', $email, \PDO::PARAM_STR);
        $statement->execute();

        return $statement->fetch();
    }

    /**
     * Insert new item in database
     */
    public function insert(array $credentials): int
    {
        $statement = $this->pdo->prepare("INSERT INTO " . static::TABLE .
            " (`email`, `password`, `pseudo`, `firstname`, `lastname`)
            VALUES (:email, :password, :pseudo, :firstname, :lastname)");
        $statement->bindValue(':email', $credentials['email']);
        $statement->bindValue(':password', password_hash($credentials['password'], PASSWORD_DEFAULT));
        $statement->bindValue(':pseudo', $credentials['pseudo']);
        $statement->bindValue(':firstname', $credentials['firstname']);
        $statement->bindValue(':lastname', $credentials['lastname']);
        $statement->execute();
        return (int)$this->pdo->lastInsertId();
    }
}
