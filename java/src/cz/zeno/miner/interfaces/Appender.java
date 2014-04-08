//Copyright 2014 Zeno Futurista (zenofuturista@gmail.com)
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

package cz.zeno.miner.interfaces;

/**
 *
 * @author zeno
 */
public interface Appender {
    //commands implementor of this interface to log this string
    //newline should be added if desirable
    public void append(String message);
}
