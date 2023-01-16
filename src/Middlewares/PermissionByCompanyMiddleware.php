<?php

namespace Orbtall\Permission\Middlewares;

use Closure;
use Orbtall\Permission\Exceptions\UnauthorizedException;

class PermissionByCompanyMiddleware {

    public function handle($request, Closure $next, $permission, $guard = null) {

        $authGuard = app('auth')->guard($guard);

        if ($authGuard->guest()) {
            throw UnauthorizedException::notLoggedIn();
        }

        $company = $request->session()->get('company');

        $permissions = is_array($permission)
            ? $permission
            : explode('|', $permission);

        foreach ($permissions as $permission) {
            if ($authGuard->user()->can($permission) && $permission->company_id == $company->id) {
                return $next($request);
            }
        }

        throw UnauthorizedException::forPermissions($permissions);

    }

}
