<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

require_once(ROOT_DIR . 'Presenters/Authentication/ExternalAuthLoginPresenter.php');
require_once(ROOT_DIR . 'lib/Application/Authentication/namespace.php');
require_once(ROOT_DIR . 'Pages/Authentication/ExternalAuthLoginPage.php');
require_once(ROOT_DIR . 'lib/Common/namespace.php');

class ExternalAuthLoginPresenterTest extends TestBase
{
    /**
     * @var FakeExternalAuthLoginPage
     */
    private $page;

    /**
     * @var FakeWebAuthentication
     */
    private $auth;

    /**
     * @var FakeRegistration
     */
    private $registration;

    /**
     * @var array
     */
    private $requestHistory = [];

    public function setUp(): void
    {
        parent::setup();

        $this->auth = new FakeWebAuthentication();
        $this->page = new FakeExternalAuthLoginPage();
        $this->registration = new FakeRegistration();
        $this->fakeConfig->_ScriptUrl = 'https://booked.example/Web';

        $this->fakeServer->SetSession(SessionKeys::USER_SESSION, new UserSession(1));

        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_URL_TOKEN, 'https://idp.example/token');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_URL_USERINFO, 'https://idp.example/userinfo');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_CLIENT_ID, 'client-id');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_CLIENT_SECRET, 'client-secret');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_REDIRECT_URI, '/Web/oauth2-auth.php');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_GROUPS_CLAIM, 'groups');

        $this->page->_Type = 'oauth2';
        $this->page->_AuthorizationCode = 'auth-code';
    }

    public function testSignupNewUser()
    {
        $this->fakeConfig->SetKey(ConfigKeys::REGISTRATION_ALLOW_SELF, 'true');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_SYNC_ON_LOGIN, 'false');
        $this->registration->_UserExists = false;

        $userInfo = $this->UserInfo();
        $presenter = $this->CreatePresenter($userInfo);
        $presenter->PageLoad();

        // Check requests from the presenter
        $this->assertCount(2, $this->requestHistory);
        $tokenRequest = $this->requestHistory[0]['request'];
        $this->assertEquals('https://idp.example/token', (string)$tokenRequest->getUri());
        parse_str((string)$tokenRequest->getBody(), $tokenParams);
        $this->assertEquals('auth-code', $tokenParams['code']);
        $this->assertEquals('https://booked.example/Web/oauth2-auth.php', $tokenParams['redirect_uri']);
        $userInfoRequest = $this->requestHistory[1]['request'];
        $this->assertEquals('https://idp.example/userinfo', (string)$userInfoRequest->getUri());
        $this->assertEquals('Bearer access-token', $userInfoRequest->getHeaderLine('Authorization'));

        // Check that attributes were correctly synced
        $this->assertEquals(ExternalAuthLoginPresenterTest::EXAMPLE_PREFERRED_USERNAME, $this->registration->_LastLogin);
        $this->assertEquals(ExternalAuthLoginPresenterTest::EXAMPLE_EMAIL, $this->registration->_LastEmail);

        $this->assertTrue($this->registration->_SynchronizeCalled);
        $user = $this->registration->_LastSynchronizedUser;
        $this->assertEquals($userInfo['preferred_username'], $user->Username());
        $this->assertEquals($userInfo['email'], $user->Email());
        $this->assertEquals($userInfo['given_name'], $user->FirstName());
        $this->assertEquals($userInfo['family_name'], $user->LastName());
        $this->assertEquals($userInfo['phone_number'], $user->Phone());
        $this->assertEquals($userInfo['organization'], $user->Organization());
        $this->assertEquals($userInfo['title'], $user->Title());
        $this->assertEquals($userInfo['groups'], $user->GetGroups());

        // Check succesful login
        $this->assertTrue($this->auth->_LoginCalled);
        $this->assertEquals($userInfo['email'], $this->auth->_LastLogin);
        $this->assertNotEmpty($this->page->_RedirectUrl);
        $this->assertNull($this->page->_Errors);
    }

    public function testSignupNewUserIsRejectedWhenSelfRegistrationIsDisabled()
    {
        $this->fakeConfig->SetKey(ConfigKeys::REGISTRATION_ALLOW_SELF, 'false');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_SYNC_ON_LOGIN, 'true');
        $this->registration->_UserExists = false;

        $presenter = $this->CreatePresenter($this->UserInfo());
        $presenter->PageLoad();

        $this->assertFalse($this->registration->_SynchronizeCalled);
        $this->assertFalse($this->auth->_LoginCalled);
        $this->assertNull($this->page->_RedirectUrl);
        $this->assertNotEmpty($this->page->_Errors);
    }

    public function testLoginExistingUser()
    {
        $this->fakeConfig->SetKey(ConfigKeys::REGISTRATION_ALLOW_SELF, 'false');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_SYNC_ON_LOGIN, 'false');
        $this->registration->_UserExists = true;

        $presenter = $this->CreatePresenter($this->UserInfo(['organization' => 'New Org']));
        $presenter->PageLoad();

        $this->assertTrue($this->auth->_LoginCalled);
        $this->assertEquals(ExternalAuthLoginPresenterTest::EXAMPLE_EMAIL, $this->auth->_LastLogin);
        $this->assertFalse($this->registration->_RegisterCalled);
        $this->assertFalse($this->registration->_SynchronizeCalled);
        $this->assertNotEmpty($this->page->_RedirectUrl);
        $this->assertNull($this->page->_Errors);
    }

    public function testLoginExistingUserSyncsAttributesWhenSyncOnLoginIsEnabled()
    {
        $this->fakeConfig->SetKey(ConfigKeys::REGISTRATION_ALLOW_SELF, 'true');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_SYNC_ON_LOGIN, 'true');
        $this->registration->_UserExists = true;

        // The user info changes between the 3 logins
        $userinfo_1 = $this->UserInfo([
            'given_name' => 'Johnny',
            'organization' => 'New Org',
            'groups' => ['new-group'],
        ]);
        $userinfo_2 = $this->UserInfo([
            'given_name' => 'Johnny',
            'organization' => 'Newer Org',
            'groups' => ['new-group', 'third-group'],
        ]);
        $userinfo_3 = $this->UserInfo([
            'given_name' => 'Johnny',
            'organization' => 'Newest Org',
            'groups' => [],
        ]);
        $userinfo_4 = $this->UserInfo([
            'given_name' => 'Johnny',
            'organization' => 'Newest Org',
            'groups' => ['new-group', 'third-group'],
        ]);
        $userinfo_5 = $this->UserInfo([
            'given_name' => 'Johnny',
            'organization' => 'Newest Org',
            'groups' => '', // empty string instead of array
        ]);
        $presenter = $this->CreatePresenter($userinfo_1, $userinfo_2, $userinfo_3, $userinfo_4, $userinfo_5);
        $presenter->PageLoad();

        $this->assertTrue($this->registration->_SynchronizeCalled);
        $user = $this->registration->_LastSynchronizedUser;
        $this->assertEquals($userinfo_1['given_name'], $user->FirstName());
        $this->assertEquals($userinfo_1['organization'], $user->Organization());
        $this->assertEquals($userinfo_1['groups'], $user->GetGroups());

        $this->assertTrue($this->auth->_LoginCalled);
        $this->assertNotEmpty($this->page->_RedirectUrl);

        // Check on second call: group added
        $this->auth->_LoginCalled = false;
        $this->registration->_SynchronizeCalled = false;
        $presenter->PageLoad();

        $this->assertTrue($this->registration->_SynchronizeCalled);
        $user = $this->registration->_LastSynchronizedUser;
        $this->assertEquals($userinfo_2['given_name'], $user->FirstName());
        $this->assertEquals($userinfo_2['organization'], $user->Organization());
        $this->assertEquals($userinfo_2['groups'], $user->GetGroups());

        $this->assertTrue($this->auth->_LoginCalled);
        $this->assertNotEmpty($this->page->_RedirectUrl);

        // Check on third call: No groups anymore
        $this->auth->_LoginCalled = false;
        $this->registration->_SynchronizeCalled = false;
        $presenter->PageLoad();

        $this->assertTrue($this->registration->_SynchronizeCalled);
        $user = $this->registration->_LastSynchronizedUser;
        $this->assertEquals($userinfo_3['given_name'], $user->FirstName());
        $this->assertEquals($userinfo_3['organization'], $user->Organization());
        $this->assertEquals($userinfo_3['groups'], $user->GetGroups());

        $this->assertTrue($this->auth->_LoginCalled);
        $this->assertNotEmpty($this->page->_RedirectUrl);

        // Fourth call: Prepare for 5th
        $this->auth->_LoginCalled = false;
        $this->registration->_SynchronizeCalled = false;
        $presenter->PageLoad();

        $this->assertTrue($this->registration->_SynchronizeCalled);
        $user = $this->registration->_LastSynchronizedUser;
        $this->assertEquals($userinfo_4['given_name'], $user->FirstName());
        $this->assertEquals($userinfo_4['organization'], $user->Organization());
        $this->assertEquals($userinfo_4['groups'], $user->GetGroups());

        // Check on fifth call: No groups anymore
        $this->auth->_LoginCalled = false;
        $this->registration->_SynchronizeCalled = false;
        $presenter->PageLoad();

        $this->assertTrue($this->registration->_SynchronizeCalled);
        $user = $this->registration->_LastSynchronizedUser;
        $this->assertEquals($userinfo_5['given_name'], $user->FirstName());
        $this->assertEquals($userinfo_5['organization'], $user->Organization());
        $this->assertEquals([], $user->GetGroups());
        // The FakeRegister does not sync groups like the real one
        // (and performs a different synchronization)

        $this->assertTrue($this->auth->_LoginCalled);
        $this->assertNotEmpty($this->page->_RedirectUrl);
    }

    public function testLoginExistingUserDoesNotSyncAttributesWhenSyncOnLoginIsDisabled()
    {
        $this->fakeConfig->SetKey(ConfigKeys::REGISTRATION_ALLOW_SELF, 'true');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_SYNC_ON_LOGIN, 'false');
        $this->registration->_UserExists = true;

        // The user info changes between the calls
        $userinfo_1 = $this->UserInfo([
            'given_name' => 'Johnny',
            'organization' => 'New Org',
            'groups' => ['new-group'],
        ]);
        $userinfo_2 = $this->UserInfo([
            'given_name' => 'Johnny II',
            'organization' => 'New Org',
            'groups' => ['new-group', 'third-group'],
        ]);
        $presenter = $this->CreatePresenter($userinfo_1, $userinfo_2);
        $presenter->PageLoad();

        $this->assertNull($this->registration->_LastSynchronizedUser);
        $this->assertFalse($this->registration->_SynchronizeCalled);

        $this->assertTrue($this->auth->_LoginCalled);
        $this->assertNotEmpty($this->page->_RedirectUrl);

        // Check on second call: sync not called
        $this->auth->_LoginCalled = false;
        $presenter->PageLoad();

        $this->assertNull($this->registration->_LastSynchronizedUser);
        $this->assertFalse($this->registration->_SynchronizeCalled);

        $this->assertTrue($this->auth->_LoginCalled);
        $this->assertNotEmpty($this->page->_RedirectUrl);
    }

    public function testLoginNewUserDoesNotSyncAttributesWhenSyncOnLoginIsDisabled()
    {
        $this->fakeConfig->SetKey(ConfigKeys::REGISTRATION_ALLOW_SELF, 'true');
        $this->fakeConfig->SetKey(ConfigKeys::AUTHENTICATION_OAUTH2_SYNC_ON_LOGIN, 'false');
        $this->registration->_UserExists = false;

        $userinfo_1 = $this->UserInfo([
            'given_name' => 'Johnny',
            'organization' => 'New Org',
            'groups' => ['new-group'],
        ]);
        $userinfo_2 = $this->UserInfo([
            'given_name' => 'Johnny II',
            'organization' => 'New Org',
            'groups' => ['new-group', 'third-group'],
        ]);
        $presenter = $this->CreatePresenter($userinfo_1, $userinfo_2);
        $presenter->PageLoad();

        $this->assertTrue($this->registration->_SynchronizeCalled);
        $user = $this->registration->_LastSynchronizedUser;
        $this->assertEquals($userinfo_1['given_name'], $user->FirstName());
        $this->assertEquals($userinfo_1['organization'], $user->Organization());
        $this->assertEquals($userinfo_1['groups'], $user->GetGroups());

        $this->assertTrue($this->auth->_LoginCalled);
        $this->assertNotEmpty($this->page->_RedirectUrl);

        // Check on second call: everything still from user 1 / not updated to user 2
        $this->auth->_LoginCalled = false;
        $this->registration->_LastSynchronizedUser = null;
        $this->registration->_SynchronizeCalled = false;
        $this->registration->_UserExists = true;
        $presenter->PageLoad();

        $this->assertNull($this->registration->_LastSynchronizedUser);
        $this->assertFalse($this->registration->_SynchronizeCalled);
        $this->assertTrue($this->auth->_LoginCalled);
    }

    /**
     * @param array $userInfos claims returned by the userinfo endpoint
     */
    private function CreatePresenter(array ...$userInfos): ExternalAuthLoginPresenter
    {
        $this->requestHistory = [];
        $responses = [];
        foreach ($userInfos as $userInfo) {
            $responses[] = new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'access-token']));
            $responses[] = new Response(200, ['Content-Type' => 'application/json'], json_encode($userInfo));
        }
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        $handlerStack->push(Middleware::history($this->requestHistory));

        $presenter = new ExternalAuthLoginPresenter(
            $this->page,
            $this->auth,
            $this->registration,
            new Client(['handler' => $handlerStack])
        );
        $this->page->presenter = $presenter;

        return $presenter;
    }

    public const EXAMPLE_PREFERRED_USERNAME = 'jdoe';
    public const EXAMPLE_EMAIL = 'jdoe@example';
    public const EXAMPLE_GIVEN_NAME = 'John';
    public const EXAMPLE_FAMILY_NAME = 'Doe';
    public const EXAMPLE_PHONE = '49-1234';
    public const EXAMPLE_ORG = 'Example Inc.';
    public const EXAMPLE_TITLE = 'Engineer';
    public const EXAMPLE_GROUPS = ['staff', 'admins'];

    private function UserInfo(array $overrides = []): array
    {
        return array_merge([
            'preferred_username' => ExternalAuthLoginPresenterTest::EXAMPLE_PREFERRED_USERNAME,
            'email' => ExternalAuthLoginPresenterTest::EXAMPLE_EMAIL,
            'given_name' => ExternalAuthLoginPresenterTest::EXAMPLE_GIVEN_NAME,
            'family_name' => ExternalAuthLoginPresenterTest::EXAMPLE_FAMILY_NAME,
            'phone_number' => ExternalAuthLoginPresenterTest::EXAMPLE_FAMILY_NAME,
            'organization' => ExternalAuthLoginPresenterTest::EXAMPLE_ORG,
            'title' => ExternalAuthLoginPresenterTest::EXAMPLE_TITLE,
            'groups' => ExternalAuthLoginPresenterTest::EXAMPLE_GROUPS,
        ], $overrides);
    }
}

class FakeExternalAuthLoginPage extends ExternalAuthLoginPage
{
    public $_Type;
    public $_AuthorizationCode;
    public $_ResumeUrl;
    public $_RedirectUrl;
    public $_Errors;

    public function __construct()
    {
        // Skip the parent constructor
    }

    public function GetType()
    {
        return $this->_Type;
    }

    public function GetAuthorizationCode()
    {
        return $this->_AuthorizationCode;
    }

    public function GetResumeUrl()
    {
        return $this->_ResumeUrl;
    }

    public function ShowError($messages)
    {
        $this->_Errors = $messages;
    }

    public function Redirect($url)
    {
        $this->_RedirectUrl = $url;
    }
}
