package de.kp.works.looker.api

/**
 * Copyright (c) 2019 - 2022 Dr. Krusche & Partner PartG. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 * @author Stefan Krusche, Dr. Krusche & Partner PartG
 *
 */

import akka.http.scaladsl.model.StatusCodes
import com.google.gson.JsonObject
import de.kp.works.looker.http.HttpConnect
import de.kp.works.looker.{LookConf, LookLogging}

import java.nio.charset.StandardCharsets
import java.security.{MessageDigest, SecureRandom}
import java.util.{Base64, Calendar, Date}

case class AuthCodeGrantType(
  client_id:String,
  redirect_uri:String,
  code:String,
  code_verifier:String,
  grant_type:String = "authorization_code") {

  def toJson:JsonObject = {

    val json = new JsonObject
    json.addProperty("client_id", client_id)
    json.addProperty("redirect_uri", redirect_uri)

    json.addProperty("code", code)
    json.addProperty("code_verifier", code_verifier)
    json.addProperty("grant_type", grant_type)

    json

  }
}

case class RefreshTokenGrantType(
  client_id:String,
  redirect_uri:String,
  refresh_token:String,
  grant_type:String = "refresh_token") {

  def toJson:JsonObject = {

    val json = new JsonObject
    json.addProperty("client_id", client_id)
    json.addProperty("redirect_uri", redirect_uri)

    json.addProperty("refresh_token", refresh_token)
    json.addProperty("grant_type", grant_type)

    json

  }

}

case class AccessToken(
  /* Access token used for API calls */
  accessToken:Option[String] = None,
  /* Type of Token */
  tokenType:Option[String] = None,
  /* Number of seconds before the token expires */
  expiresIn:Option[Int] = None,
  /* Refresh token which can be used to obtain
   * a new access token */
  refreshToken:Option[String] = None)

/**
 * Used to instantiate or check expiry
 * of an AccessToken object
 */
class AuthToken() {

  var accessToken  = ""
  var refreshToken = ""
  private var tokenType    = ""

  private val lagTime   = 10
  private var expiresIn = 0

  private var expiresAt = {

    val cal = Calendar.getInstance
    cal.setTime(new Date())

    cal.set(Calendar.SECOND, cal.get(Calendar.SECOND) - lagTime)
    cal.getTime

  }

  private var token:Option[AccessToken] = None

  def setToken(token:AccessToken):Unit = {

    this.token = Some(token)

    accessToken  = token.accessToken.getOrElse("")
    refreshToken = token.refreshToken.getOrElse("")
    tokenType    = token.tokenType.getOrElse("")

    expiresIn = token.expiresIn.getOrElse(0)
    if (token.accessToken.nonEmpty && token.expiresIn.nonEmpty) {

      val cal = Calendar.getInstance
      cal.setTime(new Date())

      cal.set(Calendar.SECOND, cal.get(Calendar.SECOND) + expiresIn - lagTime)
      expiresAt = cal.getTime

    }
    else {

      val cal = Calendar.getInstance
      cal.setTime(new Date())

      cal.set(Calendar.SECOND, cal.get(Calendar.SECOND) - lagTime)
      expiresAt = cal.getTime

    }

  }

  def isActive:Boolean = {

    val t1 = new Date().getTime
    val t2 = expiresAt.getTime

    t2 > t1

  }

}

class AuthSession extends HttpConnect with LookLogging {

  private var sudoId:Option[Int] = None
  private val apiVersion = LookConf.getApiVersion

  private var sudoToken = new AuthToken()
  protected var token = new AuthToken()


  def authenticate():Map[String,String] = {
    /*
     * Return the Authorization header to authenticate
     * each API call. Expired token renewal happens
     * automatically.
     */
    val token =
      if (sudoId.nonEmpty) getSudoToken else getToken

    val header = Map("Authorization" -> s"Bearer $token")
    header

  }

  def loginUser(sudoId:Int):Unit = {
    /*
     * Authenticate using settings credentials and sudo
     * as sudoId. Make API calls as if authenticated as
     * sudoId.
     *
     * The sudoId token is automatically renewed when it
     * expires. In order to subsequently `loginUser` as
     * another user you must first `logout`
     */

    if (this.sudoId.isEmpty) {
      this.sudoId = Some(sudoId)
      try {

      }
      catch {
        case t:Throwable =>
          val message = s"Login with sudo identifier failed: ${t.getLocalizedMessage}"
          error(message)

          this.sudoId = None
      }
    }
    else {

      if (this.sudoId.get != sudoId) {
        val message = s"Another user `${this.sudoId.get}` is logged in already."
        error(message)

      }
      else if (!isSudoAuth) {
        loginSudo()
      }
    }

  }
  /**
   * Determines if current token is active.
   */
  private def isAuthenticated(token:AuthToken):Boolean = {

    if (token.accessToken.isEmpty) return false
    token.isActive

  }

  def isAuth:Boolean = isAuthenticated(token)

  def isSudoAuth:Boolean = isAuthenticated(sudoToken)

  private def getToken:AuthToken = {
    if (!isAuth) login()
    token
  }

  private def getSudoToken:AuthToken = {
    if (!isSudoAuth) loginSudo()
    sudoToken
  }

  protected def login():Unit = {

    val clientId = LookConf.getClientId
    val clientSecret = LookConf.getClientSecret

    if (clientId.isEmpty || clientSecret.isEmpty) {
      val message = "Required authentication credentials not found."
      error(message)
    }
    else {

      val body = new JsonObject
      body.addProperty("client_id", clientId.get)
      body.addProperty("client_secret", clientSecret.get)

      val headers = Map.empty[String, String]
      val endpoint = s"${LookConf.getBaseUrl}/api/login"

      val bytes = post(endpoint = endpoint, headers = headers,
        body = body, contentType = "application/x-www-form-urlencoded")

      val json = extractJsonBody(bytes).getAsJsonObject
      this.token = extractAuthToken(json)

    }

  }

  private def loginSudo():Unit = {

    val headers = Map("Authorization" -> s"${getToken.accessToken}")
    val endpoint = s"${LookConf.getBaseUrl}/api/login/${sudoId.get}"

    val bytes = post(endpoint=endpoint, headers=headers, body=new JsonObject)

    val json = extractJsonBody(bytes).getAsJsonObject
    this.sudoToken = extractAuthToken(json)

  }

  protected def extractAuthToken(json:JsonObject):AuthToken = {

    val access_token = json.get("access_token").getAsString
    val token_type = json.get("token_type").getAsString

    val expires_in = json.get("expires_in").getAsInt
    val refresh_token = json.get("refresh_token").getAsString

    val accessToken = AccessToken(
      accessToken = Some(access_token),
      tokenType = Some(token_type),
      expiresIn = Some(expires_in),
      refreshToken = Some(refresh_token)
    )

    val authToken = new AuthToken()
    authToken.setToken(accessToken)

    authToken

  }

  /**
   * Logout of API.
   *
   * If the session is authenticated as sudo_id, logout() "undoes"
   * the sudo and deactivates that sudo_id's current token. By default
   * the current api3credential session is active at which point
   * you can continue to make API calls as the api3credential user
   * or logout(). If you want to logout completely in one step pass
   * full=True
   */
  def logout(full:Boolean = false):Unit = {

    if (sudoId.nonEmpty) {

      sudoId = None
      if (isSudoAuth) {

        doLogout(sudo=true)
        if (full) doLogout(sudo=false)

      }

    }
    else if (isAuth) {
      doLogout(sudo=false)
    }

  }

  private def doLogout(sudo:Boolean):Unit = {

    var accessToken = ""
    if (sudo) {
      accessToken = sudoToken.accessToken
      sudoToken = new AuthToken()
    }
    else {
      accessToken = token.accessToken
      token = new AuthToken()
    }

    val headers = Map("Authorization" -> s"Bearer $accessToken")
    val endpoint = s"${LookConf.getBaseUrl}/api/logout"

    val response = deleteHttp(endpoint, headers)
    val status = response.status
    if (status != StatusCodes.OK) {

      val message = s"Logout failed with: ${status.value}"
      error(message)

    }

  }
}

class CryptoHash() {

  def secureRandom(byteCount:Int):String = {

    val random = new SecureRandom()
    val bytes = new Array[Byte](byteCount)

    random.nextBytes(bytes)
    val encoder = Base64.getUrlEncoder.withoutPadding()

    encoder.encodeToString(bytes)

  }

  def sha256Hash(message:String):String = {

    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(message.getBytes(StandardCharsets.UTF_8))

    val result = new StringBuffer()
    hash.foreach(byte => {
      result.append(Integer.toString((byte & 0xff) + 0x100, 16).substring(1))
    })

    result.toString

  }

}

class OAuthSession(crypto:CryptoHash) extends AuthSession {

  private val clientId = LookConf.getClientId
  private val redirectUri = LookConf.getRedirectUri

  private val lookerUrl = LookConf.getLookerUrl
  private var codeVerifier:String = ""

  def redeemAuthCode(auth_code:String, code_verifier:Option[String] = None):Unit = {

    val params = AuthCodeGrantType(
      client_id     = clientId.get,
      redirect_uri  = redirectUri.get,
      code          = auth_code,
      code_verifier = code_verifier.getOrElse(this.codeVerifier)
    )

    this.token = getAuthTokenFromAuthCode(params)

  }

  private def getAuthTokenFromAuthCode(params:AuthCodeGrantType):AuthToken = {

    val headers = Map.empty[String,String]
    val endpoint = s"${LookConf.getBaseUrl}/api/token"

    val body = params.toJson
    val bytes = post(endpoint=endpoint, headers=headers, body=body)

    val json = extractJsonBody(bytes).getAsJsonObject
    extractAuthToken(json)

  }

  private def getAuthTokenFromRefreshToken(params:RefreshTokenGrantType):AuthToken = {

    val headers = Map.empty[String,String]
    val endpoint = s"${LookConf.getBaseUrl}/api/token"

    val body = params.toJson
    val bytes = post(endpoint=endpoint, headers=headers, body=body)

    val json = extractJsonBody(bytes).getAsJsonObject
    extractAuthToken(json)

  }

  def createAuthCodeRequestUrl(scope:String, state:String):String = {

    codeVerifier = crypto.secureRandom(32)
    val codeChallenge = crypto.sha256Hash(codeVerifier)

    val params = Map(
      "response_type"         -> "code",
      "client_id"             -> clientId.get,
      "redirect_uri"          -> redirectUri.get,
      "scope"                 -> scope,
      "state"                 -> state,
      "code_challenge_method" -> "S256",
      "code_challenge"        -> codeChallenge)

    val endpoint = s"$lookerUrl/auth"
    val query = params.map{case(k,v) => s"$k=v"}.mkString("&")

    s"$endpoint?$query"

  }

  override def login():Unit = {

    val params = RefreshTokenGrantType(
      client_id     = clientId.get,
      redirect_uri  = redirectUri.get,
      refresh_token = token.refreshToken)

    this.token = getAuthTokenFromRefreshToken(params)

  }

}
