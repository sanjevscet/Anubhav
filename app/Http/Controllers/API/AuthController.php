<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use JWTAuth;
use Validator;
use App\User;
use Response;

class AuthController extends Controller
{
    /**
     * API Register, on success return JWT Auth token.
     *
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255|unique:users',
            'name' => 'required',
            'password' => 'required',
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors());
        }
        User::create([
            'name' => $request->get('name'),
            'email' => $request->get('email'),
            'password' => bcrypt($request->get('password')),
        ]);
        $user = User::first();
        $token = JWTAuth::fromUser($user, $user->toArray());

        $status = 'success';

        return Response::json(compact('status', 'token'));
    }

    /**
     * API Login, on success return JWT Auth token.
     *
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
        $rules = [
            'email' => 'required|email',
            'password' => 'required',
        ];
        $validator = Validator::make($credentials, $rules);
        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => $validator->messages(),
            ]);
        }
        try {
            // Attempt to verify the credentials and create a token for the user
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'We can`t find an account with this credentials.',
                ], 401);
            }
        } catch (JWTException $e) {
            // Something went wrong with JWT Auth.
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to login, please try again.',
            ], 500);
        }
        // All good so return the token
        return response()->json([
            'status' => 'success',
            'data' => [
                'token' => $token,
                // You can add more details here as per you requirment.
            ],
        ]);
    }

    /**
     * Logout
     * Invalidate the token. User have to relogin to get a new token.
     *
     * @param Request $request 'header'
     */
    public function logout(Request $request)
    {
        // Get JWT Token from the request header key "Authorization"
        $token = $request->header('Authorization');

        try {
            JWTAuth::parseToken()->authenticate();
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            // do whatever you want to do if a token is expired
            return response()->json([
                'status' => 'success',
                'message' => 'Token is already expired',
            ]);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            // do whatever you want to do if a token is invalid
            return response()->json([
                'status' => 'error',
                'message' => 'Token is invalid',
            ]);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            // do whatever you want to do if a token is not present
            return response()->json([
                'status' => 'error',
                'message' => 'Sorry, Token is sent',
            ]);
        }

        // Invalidate the token
        try {
            JWTAuth::invalidate($token);

            return response()->json([
                'status' => 'success',
                'message' => 'User successfully logged out.',
            ]);
        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to logout, please try again.',
            ], 500);
        }
    }
}
