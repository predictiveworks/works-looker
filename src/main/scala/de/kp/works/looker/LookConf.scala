package de.kp.works.looker
/**
 * Copyright (c) 2020 - 2022 Dr. Krusche & Partner PartG. All rights reserved.
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

import com.typesafe.config.{Config, ConfigFactory}

object LookConf {

  private val path = "reference.conf"
  /**
   * This is the reference to the overall configuration
   * file that holds all configuration required for this
   * application
   */
  private var cfg: Option[Config] = None

  def init(config: Option[String] = None): Boolean = {

    if (cfg.isDefined) true
    else {
      try {

        cfg = if (config.isDefined) {
          /*
           * An external configuration file is provided
           * and must be transformed into a Config
           */
          Option(ConfigFactory.parseString(config.get))

        } else {
          /*
           * The internal reference file is used to
           * extract the required configurations
           */
          Option(ConfigFactory.load(path))

        }
        true

      } catch {
        case _: Throwable =>
          false
      }
    }
  }

  def isInit: Boolean = {
    cfg.isDefined
  }

  def getApiVersion:String = ???

  def getBaseUrl:String = ???

  def getClientId:Option[String] = ???

  def getClientSecret:Option[String] = ???

  def getLogFolder:String = {
    /*
     * Determine the logging folder from the system
     * property `logging.dir`. If this property is
     * not set, fallback to the logging configuration
     */
    val folder = System.getProperty("logging.dir")
    if (folder == null)
      getLoggingCfg.getString("folder")

    else folder

  }
  /**
   * This method provides the logging configuration of
   * the Works. Beat
   */
  def getLoggingCfg: Config =
    cfg.get.getConfig("logging")

  def getLookerUrl:Option[String] = ???

  def getRedirectUri:Option[String] = ???

}
