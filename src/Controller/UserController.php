<?php

namespace App\Controller;

use App\Model\UserManager;

class UserController extends AbstractController
{
    public function login(): string
    {
        $errors = [];
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // clean $_POST data
            $loginInfos = array_map('trim', $_POST);
            $loginInfos = array_map('htmlspecialchars', $loginInfos);

            foreach ($loginInfos as $field => $userInput) {
                $userInput ?: $errors[$field] = 'Ce champ doit être complété';
            }
            if (!filter_var($loginInfos['email'], FILTER_VALIDATE_EMAIL)) {
                $errors['email'] = "Une adresse mail valide est obligatoire";
            }
            // if validation is ok, insert and redirection
            if (empty($errors)) {
                $userManager = new UserManager();
                $user = $userManager->selectOneByEmail($loginInfos['email']);

                if ($user && password_verify($loginInfos['password'], $user['password'])) {
                    $_SESSION['user_id'] = $user['id'];
                    header('Location: /');
                    exit();
                }
                return $this->twig->render('User/login.html.twig');
            }

            return $this->twig->render('User/login.html.twig', [
                'errors' => $errors
            ]);
        }

        return $this->twig->render('User/login.html.twig');
    }

    public function logout()
    {
        // On supprime l'index ['user_id'] du tableau $_SESSION
        unset($_SESSION['user_id']);
        // puis on le redirige sur une autre page (page d'accueil ici)
        header('Location: /');
        exit();
    }

    public function register()
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            //      @todo make some controls and if errors send them to the view
            $credentials = array_map('trim', $_POST);
            // 1. vérifier que l'email $credentials['email'] est bien un email
            // 2. vérifier que le mot de passe $credentials['password']
            // satisfait certains critères (ex: 8 caratères, 1 majuscule, etc.)
            $userManager = new UserManager();
            // si l'insertion s'est correctement déroulée
            if ($userManager->insert($credentials)) {
                // on appelle la méthode login() pour autoconnecter l'utilisateur
                return $this->login();
            }
        }
        return $this->twig->render('User/register.html.twig');
    }
}
