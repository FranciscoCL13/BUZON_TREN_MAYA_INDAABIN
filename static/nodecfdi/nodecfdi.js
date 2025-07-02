"use strict";
var credentials = (() => {
   var Pc = Object.create;
   var mn = Object.defineProperty;
   var Vc = Object.getOwnPropertyDescriptor;
   var Mc = Object.getOwnPropertyNames;
   var Kc = Object.getPrototypeOf,
      qc = Object.prototype.hasOwnProperty;
   var gn = (e => typeof require < "u" ? require : typeof Proxy < "u" ? new Proxy(e, {
      get: (t, a) => (typeof require < "u" ? require : t)[a]
   }) : e)(function(e) {
      if (typeof require < "u") return require.apply(this, arguments);
      throw Error('Dynamic require of "' + e + '" is not supported')
   });
   var Y = (e, t) => () => (t || e((t = {
         exports: {}
      }).exports, t), t.exports),
      Hc = (e, t) => {
         for (var a in t) mn(e, a, {
            get: t[a],
            enumerable: !0
         })
      },
      so = (e, t, a, r) => {
         if (t && typeof t == "object" || typeof t == "function")
            for (let n of Mc(t)) !qc.call(e, n) && n !== a && mn(e, n, {
               get: () => t[n],
               enumerable: !(r = Vc(t, n)) || r.enumerable
            });
         return e
      };
   var Ea = (e, t, a) => (a = e != null ? Pc(Kc(e)) : {}, so(t || !e || !e.__esModule ? mn(a, "default", {
         value: e,
         enumerable: !0
      }) : a, e)),
      Gc = e => so(mn({}, "__esModule", {
         value: !0
      }), e);
   var $ = Y((og, pu) => {
      "use strict";
      pu.exports = {
         options: {
            usePureJavaScript: !1
         }
      }
   });
   var gu = Y((ug, mu) => {
      "use strict";
      var $i = {};
      mu.exports = $i;
      var yu = {};
      $i.encode = function(e, t, a) {
         if (typeof t != "string") throw new TypeError('"alphabet" must be a string.');
         if (a !== void 0 && typeof a != "number") throw new TypeError('"maxline" must be a number.');
         var r = "";
         if (!(e instanceof Uint8Array)) r = m0(e, t);
         else {
            var n = 0,
               i = t.length,
               s = t.charAt(0),
               o = [0];
            for (n = 0; n < e.length; ++n) {
               for (var u = 0, l = e[n]; u < o.length; ++u) l += o[u] << 8, o[u] = l % i, l = l / i | 0;
               for (; l > 0;) o.push(l % i), l = l / i | 0
            }
            for (n = 0; e[n] === 0 && n < e.length - 1; ++n) r += s;
            for (n = o.length - 1; n >= 0; --n) r += t[o[n]]
         }
         if (a) {
            var c = new RegExp(".{1," + a + "}", "g");
            r = r.match(c).join(`\r
`)
         }
         return r
      };
      $i.decode = function(e, t) {
         if (typeof e != "string") throw new TypeError('"input" must be a string.');
         if (typeof t != "string") throw new TypeError('"alphabet" must be a string.');
         var a = yu[t];
         if (!a) {
            a = yu[t] = [];
            for (var r = 0; r < t.length; ++r) a[t.charCodeAt(r)] = r
         }
         e = e.replace(/\s/g, "");
         for (var n = t.length, i = t.charAt(0), s = [0], r = 0; r < e.length; r++) {
            var o = a[e.charCodeAt(r)];
            if (o === void 0) return;
            for (var u = 0, l = o; u < s.length; ++u) l += s[u] * n, s[u] = l & 255, l >>= 8;
            for (; l > 0;) s.push(l & 255), l >>= 8
         }
         for (var c = 0; e[c] === i && c < e.length - 1; ++c) s.push(0);
         return typeof Buffer < "u" ? Buffer.from(s.reverse()) : new Uint8Array(s.reverse())
      };

      function m0(e, t) {
         var a = 0,
            r = t.length,
            n = t.charAt(0),
            i = [0];
         for (a = 0; a < e.length(); ++a) {
            for (var s = 0, o = e.at(a); s < i.length; ++s) o += i[s] << 8, i[s] = o % r, o = o / r | 0;
            for (; o > 0;) i.push(o % r), o = o / r | 0
         }
         var u = "";
         for (a = 0; e.at(a) === 0 && a < e.length() - 1; ++a) u += n;
         for (a = i.length - 1; a >= 0; --a) u += t[i[a]];
         return u
      }
   });
   var ae = Y((lg, xu) => {
      "use strict";
      var vu = $(),
         Eu = gu(),
         C = xu.exports = vu.util = vu.util || {};
      (function() {
         if (typeof process < "u" && process.nextTick && !process.browser) {
            C.nextTick = process.nextTick, typeof setImmediate == "function" ? C.setImmediate = setImmediate : C.setImmediate = C.nextTick;
            return
         }
         if (typeof setImmediate == "function") {
            C.setImmediate = function() {
               return setImmediate.apply(void 0, arguments)
            }, C.nextTick = function(o) {
               return setImmediate(o)
            };
            return
         }
         if (C.setImmediate = function(o) {
               setTimeout(o, 0)
            }, typeof window < "u" && typeof window.postMessage == "function") {
            let o = function(u) {
               if (u.source === window && u.data === e) {
                  u.stopPropagation();
                  var l = t.slice();
                  t.length = 0, l.forEach(function(c) {
                     c()
                  })
               }
            };
            var s = o,
               e = "forge.setImmediate",
               t = [];
            C.setImmediate = function(u) {
               t.push(u), t.length === 1 && window.postMessage(e, "*")
            }, window.addEventListener("message", o, !0)
         }
         if (typeof MutationObserver < "u") {
            var a = Date.now(),
               r = !0,
               n = document.createElement("div"),
               t = [];
            new MutationObserver(function() {
               var u = t.slice();
               t.length = 0, u.forEach(function(l) {
                  l()
               })
            }).observe(n, {
               attributes: !0
            });
            var i = C.setImmediate;
            C.setImmediate = function(u) {
               Date.now() - a > 15 ? (a = Date.now(), i(u)) : (t.push(u), t.length === 1 && n.setAttribute("a", r = !r))
            }
         }
         C.nextTick = C.setImmediate
      })();
      C.isNodejs = typeof process < "u" && process.versions && process.versions.node;
      C.globalScope = function() {
         return C.isNodejs ? global : typeof self > "u" ? window : self
      }();
      C.isArray = Array.isArray || function(e) {
         return Object.prototype.toString.call(e) === "[object Array]"
      };
      C.isArrayBuffer = function(e) {
         return typeof ArrayBuffer < "u" && e instanceof ArrayBuffer
      };
      C.isArrayBufferView = function(e) {
         return e && C.isArrayBuffer(e.buffer) && e.byteLength !== void 0
      };

      function Qa(e) {
         if (!(e === 8 || e === 16 || e === 24 || e === 32)) throw new Error("Only 8, 16, 24, or 32 bits supported: " + e)
      }
      C.ByteBuffer = ji;

      function ji(e) {
         if (this.data = "", this.read = 0, typeof e == "string") this.data = e;
         else if (C.isArrayBuffer(e) || C.isArrayBufferView(e))
            if (typeof Buffer < "u" && e instanceof Buffer) this.data = e.toString("binary");
            else {
               var t = new Uint8Array(e);
               try {
                  this.data = String.fromCharCode.apply(null, t)
               } catch {
                  for (var a = 0; a < t.length; ++a) this.putByte(t[a])
               }
            }
         else(e instanceof ji || typeof e == "object" && typeof e.data == "string" && typeof e.read == "number") && (this.data = e.data, this.read = e.read);
         this._constructedStringLength = 0
      }
      C.ByteStringBuffer = ji;
      var g0 = 4096;
      C.ByteStringBuffer.prototype._optimizeConstructedString = function(e) {
         this._constructedStringLength += e, this._constructedStringLength > g0 && (this.data.substr(0, 1), this._constructedStringLength = 0)
      };
      C.ByteStringBuffer.prototype.length = function() {
         return this.data.length - this.read
      };
      C.ByteStringBuffer.prototype.isEmpty = function() {
         return this.length() <= 0
      };
      C.ByteStringBuffer.prototype.putByte = function(e) {
         return this.putBytes(String.fromCharCode(e))
      };
      C.ByteStringBuffer.prototype.fillWithByte = function(e, t) {
         e = String.fromCharCode(e);
         for (var a = this.data; t > 0;) t & 1 && (a += e), t >>>= 1, t > 0 && (e += e);
         return this.data = a, this._optimizeConstructedString(t), this
      };
      C.ByteStringBuffer.prototype.putBytes = function(e) {
         return this.data += e, this._optimizeConstructedString(e.length), this
      };
      C.ByteStringBuffer.prototype.putString = function(e) {
         return this.putBytes(C.encodeUtf8(e))
      };
      C.ByteStringBuffer.prototype.putInt16 = function(e) {
         return this.putBytes(String.fromCharCode(e >> 8 & 255) + String.fromCharCode(e & 255))
      };
      C.ByteStringBuffer.prototype.putInt24 = function(e) {
         return this.putBytes(String.fromCharCode(e >> 16 & 255) + String.fromCharCode(e >> 8 & 255) + String.fromCharCode(e & 255))
      };
      C.ByteStringBuffer.prototype.putInt32 = function(e) {
         return this.putBytes(String.fromCharCode(e >> 24 & 255) + String.fromCharCode(e >> 16 & 255) + String.fromCharCode(e >> 8 & 255) + String.fromCharCode(e & 255))
      };
      C.ByteStringBuffer.prototype.putInt16Le = function(e) {
         return this.putBytes(String.fromCharCode(e & 255) + String.fromCharCode(e >> 8 & 255))
      };
      C.ByteStringBuffer.prototype.putInt24Le = function(e) {
         return this.putBytes(String.fromCharCode(e & 255) + String.fromCharCode(e >> 8 & 255) + String.fromCharCode(e >> 16 & 255))
      };
      C.ByteStringBuffer.prototype.putInt32Le = function(e) {
         return this.putBytes(String.fromCharCode(e & 255) + String.fromCharCode(e >> 8 & 255) + String.fromCharCode(e >> 16 & 255) + String.fromCharCode(e >> 24 & 255))
      };
      C.ByteStringBuffer.prototype.putInt = function(e, t) {
         Qa(t);
         var a = "";
         do t -= 8, a += String.fromCharCode(e >> t & 255); while (t > 0);
         return this.putBytes(a)
      };
      C.ByteStringBuffer.prototype.putSignedInt = function(e, t) {
         return e < 0 && (e += 2 << t - 1), this.putInt(e, t)
      };
      C.ByteStringBuffer.prototype.putBuffer = function(e) {
         return this.putBytes(e.getBytes())
      };
      C.ByteStringBuffer.prototype.getByte = function() {
         return this.data.charCodeAt(this.read++)
      };
      C.ByteStringBuffer.prototype.getInt16 = function() {
         var e = this.data.charCodeAt(this.read) << 8 ^ this.data.charCodeAt(this.read + 1);
         return this.read += 2, e
      };
      C.ByteStringBuffer.prototype.getInt24 = function() {
         var e = this.data.charCodeAt(this.read) << 16 ^ this.data.charCodeAt(this.read + 1) << 8 ^ this.data.charCodeAt(this.read + 2);
         return this.read += 3, e
      };
      C.ByteStringBuffer.prototype.getInt32 = function() {
         var e = this.data.charCodeAt(this.read) << 24 ^ this.data.charCodeAt(this.read + 1) << 16 ^ this.data.charCodeAt(this.read + 2) << 8 ^ this.data.charCodeAt(this.read + 3);
         return this.read += 4, e
      };
      C.ByteStringBuffer.prototype.getInt16Le = function() {
         var e = this.data.charCodeAt(this.read) ^ this.data.charCodeAt(this.read + 1) << 8;
         return this.read += 2, e
      };
      C.ByteStringBuffer.prototype.getInt24Le = function() {
         var e = this.data.charCodeAt(this.read) ^ this.data.charCodeAt(this.read + 1) << 8 ^ this.data.charCodeAt(this.read + 2) << 16;
         return this.read += 3, e
      };
      C.ByteStringBuffer.prototype.getInt32Le = function() {
         var e = this.data.charCodeAt(this.read) ^ this.data.charCodeAt(this.read + 1) << 8 ^ this.data.charCodeAt(this.read + 2) << 16 ^ this.data.charCodeAt(this.read + 3) << 24;
         return this.read += 4, e
      };
      C.ByteStringBuffer.prototype.getInt = function(e) {
         Qa(e);
         var t = 0;
         do t = (t << 8) + this.data.charCodeAt(this.read++), e -= 8; while (e > 0);
         return t
      };
      C.ByteStringBuffer.prototype.getSignedInt = function(e) {
         var t = this.getInt(e),
            a = 2 << e - 2;
         return t >= a && (t -= a << 1), t
      };
      C.ByteStringBuffer.prototype.getBytes = function(e) {
         var t;
         return e ? (e = Math.min(this.length(), e), t = this.data.slice(this.read, this.read + e), this.read += e) : e === 0 ? t = "" : (t = this.read === 0 ? this.data : this.data.slice(this.read), this.clear()), t
      };
      C.ByteStringBuffer.prototype.bytes = function(e) {
         return typeof e > "u" ? this.data.slice(this.read) : this.data.slice(this.read, this.read + e)
      };
      C.ByteStringBuffer.prototype.at = function(e) {
         return this.data.charCodeAt(this.read + e)
      };
      C.ByteStringBuffer.prototype.setAt = function(e, t) {
         return this.data = this.data.substr(0, this.read + e) + String.fromCharCode(t) + this.data.substr(this.read + e + 1), this
      };
      C.ByteStringBuffer.prototype.last = function() {
         return this.data.charCodeAt(this.data.length - 1)
      };
      C.ByteStringBuffer.prototype.copy = function() {
         var e = C.createBuffer(this.data);
         return e.read = this.read, e
      };
      C.ByteStringBuffer.prototype.compact = function() {
         return this.read > 0 && (this.data = this.data.slice(this.read), this.read = 0), this
      };
      C.ByteStringBuffer.prototype.clear = function() {
         return this.data = "", this.read = 0, this
      };
      C.ByteStringBuffer.prototype.truncate = function(e) {
         var t = Math.max(0, this.length() - e);
         return this.data = this.data.substr(this.read, t), this.read = 0, this
      };
      C.ByteStringBuffer.prototype.toHex = function() {
         for (var e = "", t = this.read; t < this.data.length; ++t) {
            var a = this.data.charCodeAt(t);
            a < 16 && (e += "0"), e += a.toString(16)
         }
         return e
      };
      C.ByteStringBuffer.prototype.toString = function() {
         return C.decodeUtf8(this.bytes())
      };

      function v0(e, t) {
         t = t || {}, this.read = t.readOffset || 0, this.growSize = t.growSize || 1024;
         var a = C.isArrayBuffer(e),
            r = C.isArrayBufferView(e);
         if (a || r) {
            a ? this.data = new DataView(e) : this.data = new DataView(e.buffer, e.byteOffset, e.byteLength), this.write = "writeOffset" in t ? t.writeOffset : this.data.byteLength;
            return
         }
         this.data = new DataView(new ArrayBuffer(0)), this.write = 0, e != null && this.putBytes(e), "writeOffset" in t && (this.write = t.writeOffset)
      }
      C.DataBuffer = v0;
      C.DataBuffer.prototype.length = function() {
         return this.write - this.read
      };
      C.DataBuffer.prototype.isEmpty = function() {
         return this.length() <= 0
      };
      C.DataBuffer.prototype.accommodate = function(e, t) {
         if (this.length() >= e) return this;
         t = Math.max(t || this.growSize, e);
         var a = new Uint8Array(this.data.buffer, this.data.byteOffset, this.data.byteLength),
            r = new Uint8Array(this.length() + t);
         return r.set(a), this.data = new DataView(r.buffer), this
      };
      C.DataBuffer.prototype.putByte = function(e) {
         return this.accommodate(1), this.data.setUint8(this.write++, e), this
      };
      C.DataBuffer.prototype.fillWithByte = function(e, t) {
         this.accommodate(t);
         for (var a = 0; a < t; ++a) this.data.setUint8(e);
         return this
      };
      C.DataBuffer.prototype.putBytes = function(e, t) {
         if (C.isArrayBufferView(e)) {
            var a = new Uint8Array(e.buffer, e.byteOffset, e.byteLength),
               r = a.byteLength - a.byteOffset;
            this.accommodate(r);
            var n = new Uint8Array(this.data.buffer, this.write);
            return n.set(a), this.write += r, this
         }
         if (C.isArrayBuffer(e)) {
            var a = new Uint8Array(e);
            this.accommodate(a.byteLength);
            var n = new Uint8Array(this.data.buffer);
            return n.set(a, this.write), this.write += a.byteLength, this
         }
         if (e instanceof C.DataBuffer || typeof e == "object" && typeof e.read == "number" && typeof e.write == "number" && C.isArrayBufferView(e.data)) {
            var a = new Uint8Array(e.data.byteLength, e.read, e.length());
            this.accommodate(a.byteLength);
            var n = new Uint8Array(e.data.byteLength, this.write);
            return n.set(a), this.write += a.byteLength, this
         }
         if (e instanceof C.ByteStringBuffer && (e = e.data, t = "binary"), t = t || "binary", typeof e == "string") {
            var i;
            if (t === "hex") return this.accommodate(Math.ceil(e.length / 2)), i = new Uint8Array(this.data.buffer, this.write), this.write += C.binary.hex.decode(e, i, this.write), this;
            if (t === "base64") return this.accommodate(Math.ceil(e.length / 4) * 3), i = new Uint8Array(this.data.buffer, this.write), this.write += C.binary.base64.decode(e, i, this.write), this;
            if (t === "utf8" && (e = C.encodeUtf8(e), t = "binary"), t === "binary" || t === "raw") return this.accommodate(e.length), i = new Uint8Array(this.data.buffer, this.write), this.write += C.binary.raw.decode(i), this;
            if (t === "utf16") return this.accommodate(e.length * 2), i = new Uint16Array(this.data.buffer, this.write), this.write += C.text.utf16.encode(i), this;
            throw new Error("Invalid encoding: " + t)
         }
         throw Error("Invalid parameter: " + e)
      };
      C.DataBuffer.prototype.putBuffer = function(e) {
         return this.putBytes(e), e.clear(), this
      };
      C.DataBuffer.prototype.putString = function(e) {
         return this.putBytes(e, "utf16")
      };
      C.DataBuffer.prototype.putInt16 = function(e) {
         return this.accommodate(2), this.data.setInt16(this.write, e), this.write += 2, this
      };
      C.DataBuffer.prototype.putInt24 = function(e) {
         return this.accommodate(3), this.data.setInt16(this.write, e >> 8 & 65535), this.data.setInt8(this.write, e >> 16 & 255), this.write += 3, this
      };
      C.DataBuffer.prototype.putInt32 = function(e) {
         return this.accommodate(4), this.data.setInt32(this.write, e), this.write += 4, this
      };
      C.DataBuffer.prototype.putInt16Le = function(e) {
         return this.accommodate(2), this.data.setInt16(this.write, e, !0), this.write += 2, this
      };
      C.DataBuffer.prototype.putInt24Le = function(e) {
         return this.accommodate(3), this.data.setInt8(this.write, e >> 16 & 255), this.data.setInt16(this.write, e >> 8 & 65535, !0), this.write += 3, this
      };
      C.DataBuffer.prototype.putInt32Le = function(e) {
         return this.accommodate(4), this.data.setInt32(this.write, e, !0), this.write += 4, this
      };
      C.DataBuffer.prototype.putInt = function(e, t) {
         Qa(t), this.accommodate(t / 8);
         do t -= 8, this.data.setInt8(this.write++, e >> t & 255); while (t > 0);
         return this
      };
      C.DataBuffer.prototype.putSignedInt = function(e, t) {
         return Qa(t), this.accommodate(t / 8), e < 0 && (e += 2 << t - 1), this.putInt(e, t)
      };
      C.DataBuffer.prototype.getByte = function() {
         return this.data.getInt8(this.read++)
      };
      C.DataBuffer.prototype.getInt16 = function() {
         var e = this.data.getInt16(this.read);
         return this.read += 2, e
      };
      C.DataBuffer.prototype.getInt24 = function() {
         var e = this.data.getInt16(this.read) << 8 ^ this.data.getInt8(this.read + 2);
         return this.read += 3, e
      };
      C.DataBuffer.prototype.getInt32 = function() {
         var e = this.data.getInt32(this.read);
         return this.read += 4, e
      };
      C.DataBuffer.prototype.getInt16Le = function() {
         var e = this.data.getInt16(this.read, !0);
         return this.read += 2, e
      };
      C.DataBuffer.prototype.getInt24Le = function() {
         var e = this.data.getInt8(this.read) ^ this.data.getInt16(this.read + 1, !0) << 8;
         return this.read += 3, e
      };
      C.DataBuffer.prototype.getInt32Le = function() {
         var e = this.data.getInt32(this.read, !0);
         return this.read += 4, e
      };
      C.DataBuffer.prototype.getInt = function(e) {
         Qa(e);
         var t = 0;
         do t = (t << 8) + this.data.getInt8(this.read++), e -= 8; while (e > 0);
         return t
      };
      C.DataBuffer.prototype.getSignedInt = function(e) {
         var t = this.getInt(e),
            a = 2 << e - 2;
         return t >= a && (t -= a << 1), t
      };
      C.DataBuffer.prototype.getBytes = function(e) {
         var t;
         return e ? (e = Math.min(this.length(), e), t = this.data.slice(this.read, this.read + e), this.read += e) : e === 0 ? t = "" : (t = this.read === 0 ? this.data : this.data.slice(this.read), this.clear()), t
      };
      C.DataBuffer.prototype.bytes = function(e) {
         return typeof e > "u" ? this.data.slice(this.read) : this.data.slice(this.read, this.read + e)
      };
      C.DataBuffer.prototype.at = function(e) {
         return this.data.getUint8(this.read + e)
      };
      C.DataBuffer.prototype.setAt = function(e, t) {
         return this.data.setUint8(e, t), this
      };
      C.DataBuffer.prototype.last = function() {
         return this.data.getUint8(this.write - 1)
      };
      C.DataBuffer.prototype.copy = function() {
         return new C.DataBuffer(this)
      };
      C.DataBuffer.prototype.compact = function() {
         if (this.read > 0) {
            var e = new Uint8Array(this.data.buffer, this.read),
               t = new Uint8Array(e.byteLength);
            t.set(e), this.data = new DataView(t), this.write -= this.read, this.read = 0
         }
         return this
      };
      C.DataBuffer.prototype.clear = function() {
         return this.data = new DataView(new ArrayBuffer(0)), this.read = this.write = 0, this
      };
      C.DataBuffer.prototype.truncate = function(e) {
         return this.write = Math.max(0, this.length() - e), this.read = Math.min(this.read, this.write), this
      };
      C.DataBuffer.prototype.toHex = function() {
         for (var e = "", t = this.read; t < this.data.byteLength; ++t) {
            var a = this.data.getUint8(t);
            a < 16 && (e += "0"), e += a.toString(16)
         }
         return e
      };
      C.DataBuffer.prototype.toString = function(e) {
         var t = new Uint8Array(this.data, this.read, this.length());
         if (e = e || "utf8", e === "binary" || e === "raw") return C.binary.raw.encode(t);
         if (e === "hex") return C.binary.hex.encode(t);
         if (e === "base64") return C.binary.base64.encode(t);
         if (e === "utf8") return C.text.utf8.decode(t);
         if (e === "utf16") return C.text.utf16.decode(t);
         throw new Error("Invalid encoding: " + e)
      };
      C.createBuffer = function(e, t) {
         return t = t || "raw", e !== void 0 && t === "utf8" && (e = C.encodeUtf8(e)), new C.ByteBuffer(e)
      };
      C.fillString = function(e, t) {
         for (var a = ""; t > 0;) t & 1 && (a += e), t >>>= 1, t > 0 && (e += e);
         return a
      };
      C.xorBytes = function(e, t, a) {
         for (var r = "", n = "", i = "", s = 0, o = 0; a > 0; --a, ++s) n = e.charCodeAt(s) ^ t.charCodeAt(s), o >= 10 && (r += i, i = "", o = 0), i += String.fromCharCode(n), ++o;
         return r += i, r
      };
      C.hexToBytes = function(e) {
         var t = "",
            a = 0;
         for (e.length & !0 && (a = 1, t += String.fromCharCode(parseInt(e[0], 16))); a < e.length; a += 2) t += String.fromCharCode(parseInt(e.substr(a, 2), 16));
         return t
      };
      C.bytesToHex = function(e) {
         return C.createBuffer(e).toHex()
      };
      C.int32ToBytes = function(e) {
         return String.fromCharCode(e >> 24 & 255) + String.fromCharCode(e >> 16 & 255) + String.fromCharCode(e >> 8 & 255) + String.fromCharCode(e & 255)
      };
      var nr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
         ir = [62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, 64, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51],
         Cu = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
      C.encode64 = function(e, t) {
         for (var a = "", r = "", n, i, s, o = 0; o < e.length;) n = e.charCodeAt(o++), i = e.charCodeAt(o++), s = e.charCodeAt(o++), a += nr.charAt(n >> 2), a += nr.charAt((n & 3) << 4 | i >> 4), isNaN(i) ? a += "==" : (a += nr.charAt((i & 15) << 2 | s >> 6), a += isNaN(s) ? "=" : nr.charAt(s & 63)), t && a.length > t && (r += a.substr(0, t) + `\r
`, a = a.substr(t));
         return r += a, r
      };
      C.decode64 = function(e) {
         e = e.replace(/[^A-Za-z0-9\+\/\=]/g, "");
         for (var t = "", a, r, n, i, s = 0; s < e.length;) a = ir[e.charCodeAt(s++) - 43], r = ir[e.charCodeAt(s++) - 43], n = ir[e.charCodeAt(s++) - 43], i = ir[e.charCodeAt(s++) - 43], t += String.fromCharCode(a << 2 | r >> 4), n !== 64 && (t += String.fromCharCode((r & 15) << 4 | n >> 2), i !== 64 && (t += String.fromCharCode((n & 3) << 6 | i)));
         return t
      };
      C.encodeUtf8 = function(e) {
         return unescape(encodeURIComponent(e))
      };
      C.decodeUtf8 = function(e) {
         return decodeURIComponent(escape(e))
      };
      C.binary = {
         raw: {},
         hex: {},
         base64: {},
         base58: {},
         baseN: {
            encode: Eu.encode,
            decode: Eu.decode
         }
      };
      C.binary.raw.encode = function(e) {
         return String.fromCharCode.apply(null, e)
      };
      C.binary.raw.decode = function(e, t, a) {
         var r = t;
         r || (r = new Uint8Array(e.length)), a = a || 0;
         for (var n = a, i = 0; i < e.length; ++i) r[n++] = e.charCodeAt(i);
         return t ? n - a : r
      };
      C.binary.hex.encode = C.bytesToHex;
      C.binary.hex.decode = function(e, t, a) {
         var r = t;
         r || (r = new Uint8Array(Math.ceil(e.length / 2))), a = a || 0;
         var n = 0,
            i = a;
         for (e.length & 1 && (n = 1, r[i++] = parseInt(e[0], 16)); n < e.length; n += 2) r[i++] = parseInt(e.substr(n, 2), 16);
         return t ? i - a : r
      };
      C.binary.base64.encode = function(e, t) {
         for (var a = "", r = "", n, i, s, o = 0; o < e.byteLength;) n = e[o++], i = e[o++], s = e[o++], a += nr.charAt(n >> 2), a += nr.charAt((n & 3) << 4 | i >> 4), isNaN(i) ? a += "==" : (a += nr.charAt((i & 15) << 2 | s >> 6), a += isNaN(s) ? "=" : nr.charAt(s & 63)), t && a.length > t && (r += a.substr(0, t) + `\r
`, a = a.substr(t));
         return r += a, r
      };
      C.binary.base64.decode = function(e, t, a) {
         var r = t;
         r || (r = new Uint8Array(Math.ceil(e.length / 4) * 3)), e = e.replace(/[^A-Za-z0-9\+\/\=]/g, ""), a = a || 0;
         for (var n, i, s, o, u = 0, l = a; u < e.length;) n = ir[e.charCodeAt(u++) - 43], i = ir[e.charCodeAt(u++) - 43], s = ir[e.charCodeAt(u++) - 43], o = ir[e.charCodeAt(u++) - 43], r[l++] = n << 2 | i >> 4, s !== 64 && (r[l++] = (i & 15) << 4 | s >> 2, o !== 64 && (r[l++] = (s & 3) << 6 | o));
         return t ? l - a : r.subarray(0, l)
      };
      C.binary.base58.encode = function(e, t) {
         return C.binary.baseN.encode(e, Cu, t)
      };
      C.binary.base58.decode = function(e, t) {
         return C.binary.baseN.decode(e, Cu, t)
      };
      C.text = {
         utf8: {},
         utf16: {}
      };
      C.text.utf8.encode = function(e, t, a) {
         e = C.encodeUtf8(e);
         var r = t;
         r || (r = new Uint8Array(e.length)), a = a || 0;
         for (var n = a, i = 0; i < e.length; ++i) r[n++] = e.charCodeAt(i);
         return t ? n - a : r
      };
      C.text.utf8.decode = function(e) {
         return C.decodeUtf8(String.fromCharCode.apply(null, e))
      };
      C.text.utf16.encode = function(e, t, a) {
         var r = t;
         r || (r = new Uint8Array(e.length * 2));
         var n = new Uint16Array(r.buffer);
         a = a || 0;
         for (var i = a, s = a, o = 0; o < e.length; ++o) n[s++] = e.charCodeAt(o), i += 2;
         return t ? i - a : r
      };
      C.text.utf16.decode = function(e) {
         return String.fromCharCode.apply(null, new Uint16Array(e.buffer))
      };
      C.deflate = function(e, t, a) {
         if (t = C.decode64(e.deflate(C.encode64(t)).rval), a) {
            var r = 2,
               n = t.charCodeAt(1);
            n & 32 && (r = 6), t = t.substring(r, t.length - 4)
         }
         return t
      };
      C.inflate = function(e, t, a) {
         var r = e.inflate(C.encode64(t)).rval;
         return r === null ? null : C.decode64(r)
      };
      var Xi = function(e, t, a) {
            if (!e) throw new Error("WebStorage not available.");
            var r;
            if (a === null ? r = e.removeItem(t) : (a = C.encode64(JSON.stringify(a)), r = e.setItem(t, a)), typeof r < "u" && r.rval !== !0) {
               var n = new Error(r.error.message);
               throw n.id = r.error.id, n.name = r.error.name, n
            }
         },
         Ji = function(e, t) {
            if (!e) throw new Error("WebStorage not available.");
            var a = e.getItem(t);
            if (e.init)
               if (a.rval === null) {
                  if (a.error) {
                     var r = new Error(a.error.message);
                     throw r.id = a.error.id, r.name = a.error.name, r
                  }
                  a = null
               } else a = a.rval;
            return a !== null && (a = JSON.parse(C.decode64(a))), a
         },
         E0 = function(e, t, a, r) {
            var n = Ji(e, t);
            n === null && (n = {}), n[a] = r, Xi(e, t, n)
         },
         C0 = function(e, t, a) {
            var r = Ji(e, t);
            return r !== null && (r = a in r ? r[a] : null), r
         },
         x0 = function(e, t, a) {
            var r = Ji(e, t);
            if (r !== null && a in r) {
               delete r[a];
               var n = !0;
               for (var i in r) {
                  n = !1;
                  break
               }
               n && (r = null), Xi(e, t, r)
            }
         },
         T0 = function(e, t) {
            Xi(e, t, null)
         },
         Ln = function(e, t, a) {
            var r = null;
            typeof a > "u" && (a = ["web", "flash"]);
            var n, i = !1,
               s = null;
            for (var o in a) {
               n = a[o];
               try {
                  if (n === "flash" || n === "both") {
                     if (t[0] === null) throw new Error("Flash local storage not available.");
                     r = e.apply(this, t), i = n === "flash"
                  }(n === "web" || n === "both") && (t[0] = localStorage, r = e.apply(this, t), i = !0)
               } catch (u) {
                  s = u
               }
               if (i) break
            }
            if (!i) throw s;
            return r
         };
      C.setItem = function(e, t, a, r, n) {
         Ln(E0, arguments, n)
      };
      C.getItem = function(e, t, a, r) {
         return Ln(C0, arguments, r)
      };
      C.removeItem = function(e, t, a, r) {
         Ln(x0, arguments, r)
      };
      C.clearItems = function(e, t, a) {
         Ln(T0, arguments, a)
      };
      C.isEmpty = function(e) {
         for (var t in e)
            if (e.hasOwnProperty(t)) return !1;
         return !0
      };
      C.format = function(e) {
         for (var t = /%./g, a, r, n = 0, i = [], s = 0; a = t.exec(e);) {
            r = e.substring(s, t.lastIndex - 2), r.length > 0 && i.push(r), s = t.lastIndex;
            var o = a[0][1];
            switch (o) {
               case "s":
               case "o":
                  n < arguments.length ? i.push(arguments[n++ + 1]) : i.push("<?>");
                  break;
               case "%":
                  i.push("%");
                  break;
               default:
                  i.push("<%" + o + "?>")
            }
         }
         return i.push(e.substring(s)), i.join("")
      };
      C.formatNumber = function(e, t, a, r) {
         var n = e,
            i = isNaN(t = Math.abs(t)) ? 2 : t,
            s = a === void 0 ? "," : a,
            o = r === void 0 ? "." : r,
            u = n < 0 ? "-" : "",
            l = parseInt(n = Math.abs(+n || 0).toFixed(i), 10) + "",
            c = l.length > 3 ? l.length % 3 : 0;
         return u + (c ? l.substr(0, c) + o : "") + l.substr(c).replace(/(\d{3})(?=\d)/g, "$1" + o) + (i ? s + Math.abs(n - l).toFixed(i).slice(2) : "")
      };
      C.formatSize = function(e) {
         return e >= 1073741824 ? e = C.formatNumber(e / 1073741824, 2, ".", "") + " GiB" : e >= 1048576 ? e = C.formatNumber(e / 1048576, 2, ".", "") + " MiB" : e >= 1024 ? e = C.formatNumber(e / 1024, 0) + " KiB" : e = C.formatNumber(e, 0) + " bytes", e
      };
      C.bytesFromIP = function(e) {
         return e.indexOf(".") !== -1 ? C.bytesFromIPv4(e) : e.indexOf(":") !== -1 ? C.bytesFromIPv6(e) : null
      };
      C.bytesFromIPv4 = function(e) {
         if (e = e.split("."), e.length !== 4) return null;
         for (var t = C.createBuffer(), a = 0; a < e.length; ++a) {
            var r = parseInt(e[a], 10);
            if (isNaN(r)) return null;
            t.putByte(r)
         }
         return t.getBytes()
      };
      C.bytesFromIPv6 = function(e) {
         var t = 0;
         e = e.split(":").filter(function(s) {
            return s.length === 0 && ++t, !0
         });
         for (var a = (8 - e.length + t) * 2, r = C.createBuffer(), n = 0; n < 8; ++n) {
            if (!e[n] || e[n].length === 0) {
               r.fillWithByte(0, a), a = 0;
               continue
            }
            var i = C.hexToBytes(e[n]);
            i.length < 2 && r.putByte(0), r.putBytes(i)
         }
         return r.getBytes()
      };
      C.bytesToIP = function(e) {
         return e.length === 4 ? C.bytesToIPv4(e) : e.length === 16 ? C.bytesToIPv6(e) : null
      };
      C.bytesToIPv4 = function(e) {
         if (e.length !== 4) return null;
         for (var t = [], a = 0; a < e.length; ++a) t.push(e.charCodeAt(a));
         return t.join(".")
      };
      C.bytesToIPv6 = function(e) {
         if (e.length !== 16) return null;
         for (var t = [], a = [], r = 0, n = 0; n < e.length; n += 2) {
            for (var i = C.bytesToHex(e[n] + e[n + 1]); i[0] === "0" && i !== "0";) i = i.substr(1);
            if (i === "0") {
               var s = a[a.length - 1],
                  o = t.length;
               !s || o !== s.end + 1 ? a.push({
                  start: o,
                  end: o
               }) : (s.end = o, s.end - s.start > a[r].end - a[r].start && (r = a.length - 1))
            }
            t.push(i)
         }
         if (a.length > 0) {
            var u = a[r];
            u.end - u.start > 0 && (t.splice(u.start, u.end - u.start + 1, ""), u.start === 0 && t.unshift(""), u.end === 7 && t.push(""))
         }
         return t.join(":")
      };
      C.estimateCores = function(e, t) {
         if (typeof e == "function" && (t = e, e = {}), e = e || {}, "cores" in C && !e.update) return t(null, C.cores);
         if (typeof navigator < "u" && "hardwareConcurrency" in navigator && navigator.hardwareConcurrency > 0) return C.cores = navigator.hardwareConcurrency, t(null, C.cores);
         if (typeof Worker > "u") return C.cores = 1, t(null, C.cores);
         if (typeof Blob > "u") return C.cores = 2, t(null, C.cores);
         var a = URL.createObjectURL(new Blob(["(", function() {
            self.addEventListener("message", function(s) {
               for (var o = Date.now(), u = o + 4; Date.now() < u;);
               self.postMessage({
                  st: o,
                  et: u
               })
            })
         }.toString(), ")()"], {
            type: "application/javascript"
         }));
         r([], 5, 16);

         function r(s, o, u) {
            if (o === 0) {
               var l = Math.floor(s.reduce(function(c, f) {
                  return c + f
               }, 0) / s.length);
               return C.cores = Math.max(1, l), URL.revokeObjectURL(a), t(null, C.cores)
            }
            n(u, function(c, f) {
               s.push(i(u, f)), r(s, o - 1, u)
            })
         }

         function n(s, o) {
            for (var u = [], l = [], c = 0; c < s; ++c) {
               var f = new Worker(a);
               f.addEventListener("message", function(y) {
                  if (l.push(y.data), l.length === s) {
                     for (var g = 0; g < s; ++g) u[g].terminate();
                     o(null, l)
                  }
               }), u.push(f)
            }
            for (var c = 0; c < s; ++c) u[c].postMessage(c)
         }

         function i(s, o) {
            for (var u = [], l = 0; l < s; ++l)
               for (var c = o[l], f = u[l] = [], y = 0; y < s; ++y)
                  if (l !== y) {
                     var g = o[y];
                     (c.st > g.st && c.st < g.et || g.st > c.st && g.st < c.et) && f.push(y)
                  } return u.reduce(function(m, x) {
               return Math.max(m, x.length)
            }, 0)
         }
      }
   });
   var kn = Y((cg, Tu) => {
      "use strict";
      var Le = $();
      ae();
      Tu.exports = Le.cipher = Le.cipher || {};
      Le.cipher.algorithms = Le.cipher.algorithms || {};
      Le.cipher.createCipher = function(e, t) {
         var a = e;
         if (typeof a == "string" && (a = Le.cipher.getAlgorithm(a), a && (a = a())), !a) throw new Error("Unsupported algorithm: " + e);
         return new Le.cipher.BlockCipher({
            algorithm: a,
            key: t,
            decrypt: !1
         })
      };
      Le.cipher.createDecipher = function(e, t) {
         var a = e;
         if (typeof a == "string" && (a = Le.cipher.getAlgorithm(a), a && (a = a())), !a) throw new Error("Unsupported algorithm: " + e);
         return new Le.cipher.BlockCipher({
            algorithm: a,
            key: t,
            decrypt: !0
         })
      };
      Le.cipher.registerAlgorithm = function(e, t) {
         e = e.toUpperCase(), Le.cipher.algorithms[e] = t
      };
      Le.cipher.getAlgorithm = function(e) {
         return e = e.toUpperCase(), e in Le.cipher.algorithms ? Le.cipher.algorithms[e] : null
      };
      var es = Le.cipher.BlockCipher = function(e) {
         this.algorithm = e.algorithm, this.mode = this.algorithm.mode, this.blockSize = this.mode.blockSize, this._finish = !1, this._input = null, this.output = null, this._op = e.decrypt ? this.mode.decrypt : this.mode.encrypt, this._decrypt = e.decrypt, this.algorithm.initialize(e)
      };
      es.prototype.start = function(e) {
         e = e || {};
         var t = {};
         for (var a in e) t[a] = e[a];
         t.decrypt = this._decrypt, this._finish = !1, this._input = Le.util.createBuffer(), this.output = e.output || Le.util.createBuffer(), this.mode.start(t)
      };
      es.prototype.update = function(e) {
         for (e && this._input.putBuffer(e); !this._op.call(this.mode, this._input, this.output, this._finish) && !this._finish;);
         this._input.compact()
      };
      es.prototype.finish = function(e) {
         e && (this.mode.name === "ECB" || this.mode.name === "CBC") && (this.mode.pad = function(a) {
            return e(this.blockSize, a, !1)
         }, this.mode.unpad = function(a) {
            return e(this.blockSize, a, !0)
         });
         var t = {};
         return t.decrypt = this._decrypt, t.overflow = this._input.length() % this.blockSize, !(!this._decrypt && this.mode.pad && !this.mode.pad(this._input, t) || (this._finish = !0, this.update(), this._decrypt && this.mode.unpad && !this.mode.unpad(this.output, t)) || this.mode.afterFinish && !this.mode.afterFinish(this.output, t))
      }
   });
   var rs = Y((fg, Su) => {
      "use strict";
      var ke = $();
      ae();
      ke.cipher = ke.cipher || {};
      var j = Su.exports = ke.cipher.modes = ke.cipher.modes || {};
      j.ecb = function(e) {
         e = e || {}, this.name = "ECB", this.cipher = e.cipher, this.blockSize = e.blockSize || 16, this._ints = this.blockSize / 4, this._inBlock = new Array(this._ints), this._outBlock = new Array(this._ints)
      };
      j.ecb.prototype.start = function(e) {};
      j.ecb.prototype.encrypt = function(e, t, a) {
         if (e.length() < this.blockSize && !(a && e.length() > 0)) return !0;
         for (var r = 0; r < this._ints; ++r) this._inBlock[r] = e.getInt32();
         this.cipher.encrypt(this._inBlock, this._outBlock);
         for (var r = 0; r < this._ints; ++r) t.putInt32(this._outBlock[r])
      };
      j.ecb.prototype.decrypt = function(e, t, a) {
         if (e.length() < this.blockSize && !(a && e.length() > 0)) return !0;
         for (var r = 0; r < this._ints; ++r) this._inBlock[r] = e.getInt32();
         this.cipher.decrypt(this._inBlock, this._outBlock);
         for (var r = 0; r < this._ints; ++r) t.putInt32(this._outBlock[r])
      };
      j.ecb.prototype.pad = function(e, t) {
         var a = e.length() === this.blockSize ? this.blockSize : this.blockSize - e.length();
         return e.fillWithByte(a, a), !0
      };
      j.ecb.prototype.unpad = function(e, t) {
         if (t.overflow > 0) return !1;
         var a = e.length(),
            r = e.at(a - 1);
         return r > this.blockSize << 2 ? !1 : (e.truncate(r), !0)
      };
      j.cbc = function(e) {
         e = e || {}, this.name = "CBC", this.cipher = e.cipher, this.blockSize = e.blockSize || 16, this._ints = this.blockSize / 4, this._inBlock = new Array(this._ints), this._outBlock = new Array(this._ints)
      };
      j.cbc.prototype.start = function(e) {
         if (e.iv === null) {
            if (!this._prev) throw new Error("Invalid IV parameter.");
            this._iv = this._prev.slice(0)
         } else if ("iv" in e) this._iv = On(e.iv, this.blockSize), this._prev = this._iv.slice(0);
         else throw new Error("Invalid IV parameter.")
      };
      j.cbc.prototype.encrypt = function(e, t, a) {
         if (e.length() < this.blockSize && !(a && e.length() > 0)) return !0;
         for (var r = 0; r < this._ints; ++r) this._inBlock[r] = this._prev[r] ^ e.getInt32();
         this.cipher.encrypt(this._inBlock, this._outBlock);
         for (var r = 0; r < this._ints; ++r) t.putInt32(this._outBlock[r]);
         this._prev = this._outBlock
      };
      j.cbc.prototype.decrypt = function(e, t, a) {
         if (e.length() < this.blockSize && !(a && e.length() > 0)) return !0;
         for (var r = 0; r < this._ints; ++r) this._inBlock[r] = e.getInt32();
         this.cipher.decrypt(this._inBlock, this._outBlock);
         for (var r = 0; r < this._ints; ++r) t.putInt32(this._prev[r] ^ this._outBlock[r]);
         this._prev = this._inBlock.slice(0)
      };
      j.cbc.prototype.pad = function(e, t) {
         var a = e.length() === this.blockSize ? this.blockSize : this.blockSize - e.length();
         return e.fillWithByte(a, a), !0
      };
      j.cbc.prototype.unpad = function(e, t) {
         if (t.overflow > 0) return !1;
         var a = e.length(),
            r = e.at(a - 1);
         return r > this.blockSize << 2 ? !1 : (e.truncate(r), !0)
      };
      j.cfb = function(e) {
         e = e || {}, this.name = "CFB", this.cipher = e.cipher, this.blockSize = e.blockSize || 16, this._ints = this.blockSize / 4, this._inBlock = null, this._outBlock = new Array(this._ints), this._partialBlock = new Array(this._ints), this._partialOutput = ke.util.createBuffer(), this._partialBytes = 0
      };
      j.cfb.prototype.start = function(e) {
         if (!("iv" in e)) throw new Error("Invalid IV parameter.");
         this._iv = On(e.iv, this.blockSize), this._inBlock = this._iv.slice(0), this._partialBytes = 0
      };
      j.cfb.prototype.encrypt = function(e, t, a) {
         var r = e.length();
         if (r === 0) return !0;
         if (this.cipher.encrypt(this._inBlock, this._outBlock), this._partialBytes === 0 && r >= this.blockSize) {
            for (var n = 0; n < this._ints; ++n) this._inBlock[n] = e.getInt32() ^ this._outBlock[n], t.putInt32(this._inBlock[n]);
            return
         }
         var i = (this.blockSize - r) % this.blockSize;
         i > 0 && (i = this.blockSize - i), this._partialOutput.clear();
         for (var n = 0; n < this._ints; ++n) this._partialBlock[n] = e.getInt32() ^ this._outBlock[n], this._partialOutput.putInt32(this._partialBlock[n]);
         if (i > 0) e.read -= this.blockSize;
         else
            for (var n = 0; n < this._ints; ++n) this._inBlock[n] = this._partialBlock[n];
         if (this._partialBytes > 0 && this._partialOutput.getBytes(this._partialBytes), i > 0 && !a) return t.putBytes(this._partialOutput.getBytes(i - this._partialBytes)), this._partialBytes = i, !0;
         t.putBytes(this._partialOutput.getBytes(r - this._partialBytes)), this._partialBytes = 0
      };
      j.cfb.prototype.decrypt = function(e, t, a) {
         var r = e.length();
         if (r === 0) return !0;
         if (this.cipher.encrypt(this._inBlock, this._outBlock), this._partialBytes === 0 && r >= this.blockSize) {
            for (var n = 0; n < this._ints; ++n) this._inBlock[n] = e.getInt32(), t.putInt32(this._inBlock[n] ^ this._outBlock[n]);
            return
         }
         var i = (this.blockSize - r) % this.blockSize;
         i > 0 && (i = this.blockSize - i), this._partialOutput.clear();
         for (var n = 0; n < this._ints; ++n) this._partialBlock[n] = e.getInt32(), this._partialOutput.putInt32(this._partialBlock[n] ^ this._outBlock[n]);
         if (i > 0) e.read -= this.blockSize;
         else
            for (var n = 0; n < this._ints; ++n) this._inBlock[n] = this._partialBlock[n];
         if (this._partialBytes > 0 && this._partialOutput.getBytes(this._partialBytes), i > 0 && !a) return t.putBytes(this._partialOutput.getBytes(i - this._partialBytes)), this._partialBytes = i, !0;
         t.putBytes(this._partialOutput.getBytes(r - this._partialBytes)), this._partialBytes = 0
      };
      j.ofb = function(e) {
         e = e || {}, this.name = "OFB", this.cipher = e.cipher, this.blockSize = e.blockSize || 16, this._ints = this.blockSize / 4, this._inBlock = null, this._outBlock = new Array(this._ints), this._partialOutput = ke.util.createBuffer(), this._partialBytes = 0
      };
      j.ofb.prototype.start = function(e) {
         if (!("iv" in e)) throw new Error("Invalid IV parameter.");
         this._iv = On(e.iv, this.blockSize), this._inBlock = this._iv.slice(0), this._partialBytes = 0
      };
      j.ofb.prototype.encrypt = function(e, t, a) {
         var r = e.length();
         if (e.length() === 0) return !0;
         if (this.cipher.encrypt(this._inBlock, this._outBlock), this._partialBytes === 0 && r >= this.blockSize) {
            for (var n = 0; n < this._ints; ++n) t.putInt32(e.getInt32() ^ this._outBlock[n]), this._inBlock[n] = this._outBlock[n];
            return
         }
         var i = (this.blockSize - r) % this.blockSize;
         i > 0 && (i = this.blockSize - i), this._partialOutput.clear();
         for (var n = 0; n < this._ints; ++n) this._partialOutput.putInt32(e.getInt32() ^ this._outBlock[n]);
         if (i > 0) e.read -= this.blockSize;
         else
            for (var n = 0; n < this._ints; ++n) this._inBlock[n] = this._outBlock[n];
         if (this._partialBytes > 0 && this._partialOutput.getBytes(this._partialBytes), i > 0 && !a) return t.putBytes(this._partialOutput.getBytes(i - this._partialBytes)), this._partialBytes = i, !0;
         t.putBytes(this._partialOutput.getBytes(r - this._partialBytes)), this._partialBytes = 0
      };
      j.ofb.prototype.decrypt = j.ofb.prototype.encrypt;
      j.ctr = function(e) {
         e = e || {}, this.name = "CTR", this.cipher = e.cipher, this.blockSize = e.blockSize || 16, this._ints = this.blockSize / 4, this._inBlock = null, this._outBlock = new Array(this._ints), this._partialOutput = ke.util.createBuffer(), this._partialBytes = 0
      };
      j.ctr.prototype.start = function(e) {
         if (!("iv" in e)) throw new Error("Invalid IV parameter.");
         this._iv = On(e.iv, this.blockSize), this._inBlock = this._iv.slice(0), this._partialBytes = 0
      };
      j.ctr.prototype.encrypt = function(e, t, a) {
         var r = e.length();
         if (r === 0) return !0;
         if (this.cipher.encrypt(this._inBlock, this._outBlock), this._partialBytes === 0 && r >= this.blockSize)
            for (var n = 0; n < this._ints; ++n) t.putInt32(e.getInt32() ^ this._outBlock[n]);
         else {
            var i = (this.blockSize - r) % this.blockSize;
            i > 0 && (i = this.blockSize - i), this._partialOutput.clear();
            for (var n = 0; n < this._ints; ++n) this._partialOutput.putInt32(e.getInt32() ^ this._outBlock[n]);
            if (i > 0 && (e.read -= this.blockSize), this._partialBytes > 0 && this._partialOutput.getBytes(this._partialBytes), i > 0 && !a) return t.putBytes(this._partialOutput.getBytes(i - this._partialBytes)), this._partialBytes = i, !0;
            t.putBytes(this._partialOutput.getBytes(r - this._partialBytes)), this._partialBytes = 0
         }
         Un(this._inBlock)
      };
      j.ctr.prototype.decrypt = j.ctr.prototype.encrypt;
      j.gcm = function(e) {
         e = e || {}, this.name = "GCM", this.cipher = e.cipher, this.blockSize = e.blockSize || 16, this._ints = this.blockSize / 4, this._inBlock = new Array(this._ints), this._outBlock = new Array(this._ints), this._partialOutput = ke.util.createBuffer(), this._partialBytes = 0, this._R = 3774873600
      };
      j.gcm.prototype.start = function(e) {
         if (!("iv" in e)) throw new Error("Invalid IV parameter.");
         var t = ke.util.createBuffer(e.iv);
         this._cipherLength = 0;
         var a;
         if ("additionalData" in e ? a = ke.util.createBuffer(e.additionalData) : a = ke.util.createBuffer(), "tagLength" in e ? this._tagLength = e.tagLength : this._tagLength = 128, this._tag = null, e.decrypt && (this._tag = ke.util.createBuffer(e.tag).getBytes(), this._tag.length !== this._tagLength / 8)) throw new Error("Authentication tag does not match tag length.");
         this._hashBlock = new Array(this._ints), this.tag = null, this._hashSubkey = new Array(this._ints), this.cipher.encrypt([0, 0, 0, 0], this._hashSubkey), this.componentBits = 4, this._m = this.generateHashTable(this._hashSubkey, this.componentBits);
         var r = t.length();
         if (r === 12) this._j0 = [t.getInt32(), t.getInt32(), t.getInt32(), 1];
         else {
            for (this._j0 = [0, 0, 0, 0]; t.length() > 0;) this._j0 = this.ghash(this._hashSubkey, this._j0, [t.getInt32(), t.getInt32(), t.getInt32(), t.getInt32()]);
            this._j0 = this.ghash(this._hashSubkey, this._j0, [0, 0].concat(ts(r * 8)))
         }
         this._inBlock = this._j0.slice(0), Un(this._inBlock), this._partialBytes = 0, a = ke.util.createBuffer(a), this._aDataLength = ts(a.length() * 8);
         var n = a.length() % this.blockSize;
         for (n && a.fillWithByte(0, this.blockSize - n), this._s = [0, 0, 0, 0]; a.length() > 0;) this._s = this.ghash(this._hashSubkey, this._s, [a.getInt32(), a.getInt32(), a.getInt32(), a.getInt32()])
      };
      j.gcm.prototype.encrypt = function(e, t, a) {
         var r = e.length();
         if (r === 0) return !0;
         if (this.cipher.encrypt(this._inBlock, this._outBlock), this._partialBytes === 0 && r >= this.blockSize) {
            for (var n = 0; n < this._ints; ++n) t.putInt32(this._outBlock[n] ^= e.getInt32());
            this._cipherLength += this.blockSize
         } else {
            var i = (this.blockSize - r) % this.blockSize;
            i > 0 && (i = this.blockSize - i), this._partialOutput.clear();
            for (var n = 0; n < this._ints; ++n) this._partialOutput.putInt32(e.getInt32() ^ this._outBlock[n]);
            if (i <= 0 || a) {
               if (a) {
                  var s = r % this.blockSize;
                  this._cipherLength += s, this._partialOutput.truncate(this.blockSize - s)
               } else this._cipherLength += this.blockSize;
               for (var n = 0; n < this._ints; ++n) this._outBlock[n] = this._partialOutput.getInt32();
               this._partialOutput.read -= this.blockSize
            }
            if (this._partialBytes > 0 && this._partialOutput.getBytes(this._partialBytes), i > 0 && !a) return e.read -= this.blockSize, t.putBytes(this._partialOutput.getBytes(i - this._partialBytes)), this._partialBytes = i, !0;
            t.putBytes(this._partialOutput.getBytes(r - this._partialBytes)), this._partialBytes = 0
         }
         this._s = this.ghash(this._hashSubkey, this._s, this._outBlock), Un(this._inBlock)
      };
      j.gcm.prototype.decrypt = function(e, t, a) {
         var r = e.length();
         if (r < this.blockSize && !(a && r > 0)) return !0;
         this.cipher.encrypt(this._inBlock, this._outBlock), Un(this._inBlock), this._hashBlock[0] = e.getInt32(), this._hashBlock[1] = e.getInt32(), this._hashBlock[2] = e.getInt32(), this._hashBlock[3] = e.getInt32(), this._s = this.ghash(this._hashSubkey, this._s, this._hashBlock);
         for (var n = 0; n < this._ints; ++n) t.putInt32(this._outBlock[n] ^ this._hashBlock[n]);
         r < this.blockSize ? this._cipherLength += r % this.blockSize : this._cipherLength += this.blockSize
      };
      j.gcm.prototype.afterFinish = function(e, t) {
         var a = !0;
         t.decrypt && t.overflow && e.truncate(this.blockSize - t.overflow), this.tag = ke.util.createBuffer();
         var r = this._aDataLength.concat(ts(this._cipherLength * 8));
         this._s = this.ghash(this._hashSubkey, this._s, r);
         var n = [];
         this.cipher.encrypt(this._j0, n);
         for (var i = 0; i < this._ints; ++i) this.tag.putInt32(this._s[i] ^ n[i]);
         return this.tag.truncate(this.tag.length() % (this._tagLength / 8)), t.decrypt && this.tag.bytes() !== this._tag && (a = !1), a
      };
      j.gcm.prototype.multiply = function(e, t) {
         for (var a = [0, 0, 0, 0], r = t.slice(0), n = 0; n < 128; ++n) {
            var i = e[n / 32 | 0] & 1 << 31 - n % 32;
            i && (a[0] ^= r[0], a[1] ^= r[1], a[2] ^= r[2], a[3] ^= r[3]), this.pow(r, r)
         }
         return a
      };
      j.gcm.prototype.pow = function(e, t) {
         for (var a = e[3] & 1, r = 3; r > 0; --r) t[r] = e[r] >>> 1 | (e[r - 1] & 1) << 31;
         t[0] = e[0] >>> 1, a && (t[0] ^= this._R)
      };
      j.gcm.prototype.tableMultiply = function(e) {
         for (var t = [0, 0, 0, 0], a = 0; a < 32; ++a) {
            var r = a / 8 | 0,
               n = e[r] >>> (7 - a % 8) * 4 & 15,
               i = this._m[a][n];
            t[0] ^= i[0], t[1] ^= i[1], t[2] ^= i[2], t[3] ^= i[3]
         }
         return t
      };
      j.gcm.prototype.ghash = function(e, t, a) {
         return t[0] ^= a[0], t[1] ^= a[1], t[2] ^= a[2], t[3] ^= a[3], this.tableMultiply(t)
      };
      j.gcm.prototype.generateHashTable = function(e, t) {
         for (var a = 8 / t, r = 4 * a, n = 16 * a, i = new Array(n), s = 0; s < n; ++s) {
            var o = [0, 0, 0, 0],
               u = s / r | 0,
               l = (r - 1 - s % r) * t;
            o[u] = 1 << t - 1 << l, i[s] = this.generateSubHashTable(this.multiply(o, e), t)
         }
         return i
      };
      j.gcm.prototype.generateSubHashTable = function(e, t) {
         var a = 1 << t,
            r = a >>> 1,
            n = new Array(a);
         n[r] = e.slice(0);
         for (var i = r >>> 1; i > 0;) this.pow(n[2 * i], n[i] = []), i >>= 1;
         for (i = 2; i < r;) {
            for (var s = 1; s < i; ++s) {
               var o = n[i],
                  u = n[s];
               n[i + s] = [o[0] ^ u[0], o[1] ^ u[1], o[2] ^ u[2], o[3] ^ u[3]]
            }
            i *= 2
         }
         for (n[0] = [0, 0, 0, 0], i = r + 1; i < a; ++i) {
            var l = n[i ^ r];
            n[i] = [e[0] ^ l[0], e[1] ^ l[1], e[2] ^ l[2], e[3] ^ l[3]]
         }
         return n
      };

      function On(e, t) {
         if (typeof e == "string" && (e = ke.util.createBuffer(e)), ke.util.isArray(e) && e.length > 4) {
            var a = e;
            e = ke.util.createBuffer();
            for (var r = 0; r < a.length; ++r) e.putByte(a[r])
         }
         if (e.length() < t) throw new Error("Invalid IV length; got " + e.length() + " bytes and expected " + t + " bytes.");
         if (!ke.util.isArray(e)) {
            for (var n = [], i = t / 4, r = 0; r < i; ++r) n.push(e.getInt32());
            e = n
         }
         return e
      }

      function Un(e) {
         e[e.length - 1] = e[e.length - 1] + 1 & 4294967295
      }

      function ts(e) {
         return [e / 4294967296 | 0, e & 4294967295]
      }
   });
   var sr = Y((hg, Bu) => {
      "use strict";
      var ye = $();
      kn();
      rs();
      ae();
      Bu.exports = ye.aes = ye.aes || {};
      ye.aes.startEncrypting = function(e, t, a, r) {
         var n = Fn({
            key: e,
            output: a,
            decrypt: !1,
            mode: r
         });
         return n.start(t), n
      };
      ye.aes.createEncryptionCipher = function(e, t) {
         return Fn({
            key: e,
            output: null,
            decrypt: !1,
            mode: t
         })
      };
      ye.aes.startDecrypting = function(e, t, a, r) {
         var n = Fn({
            key: e,
            output: a,
            decrypt: !0,
            mode: r
         });
         return n.start(t), n
      };
      ye.aes.createDecryptionCipher = function(e, t) {
         return Fn({
            key: e,
            output: null,
            decrypt: !0,
            mode: t
         })
      };
      ye.aes.Algorithm = function(e, t) {
         is || bu();
         var a = this;
         a.name = e, a.mode = new t({
            blockSize: 16,
            cipher: {
               encrypt: function(r, n) {
                  return ns(a._w, r, n, !1)
               },
               decrypt: function(r, n) {
                  return ns(a._w, r, n, !0)
               }
            }
         }), a._init = !1
      };
      ye.aes.Algorithm.prototype.initialize = function(e) {
         if (!this._init) {
            var t = e.key,
               a;
            if (typeof t == "string" && (t.length === 16 || t.length === 24 || t.length === 32)) t = ye.util.createBuffer(t);
            else if (ye.util.isArray(t) && (t.length === 16 || t.length === 24 || t.length === 32)) {
               a = t, t = ye.util.createBuffer();
               for (var r = 0; r < a.length; ++r) t.putByte(a[r])
            }
            if (!ye.util.isArray(t)) {
               a = t, t = [];
               var n = a.length();
               if (n === 16 || n === 24 || n === 32) {
                  n = n >>> 2;
                  for (var r = 0; r < n; ++r) t.push(a.getInt32())
               }
            }
            if (!ye.util.isArray(t) || !(t.length === 4 || t.length === 6 || t.length === 8)) throw new Error("Invalid key parameter.");
            var i = this.mode.name,
               s = ["CFB", "OFB", "CTR", "GCM"].indexOf(i) !== -1;
            this._w = Au(t, e.decrypt && !s), this._init = !0
         }
      };
      ye.aes._expandKey = function(e, t) {
         return is || bu(), Au(e, t)
      };
      ye.aes._updateBlock = ns;
      Xr("AES-ECB", ye.cipher.modes.ecb);
      Xr("AES-CBC", ye.cipher.modes.cbc);
      Xr("AES-CFB", ye.cipher.modes.cfb);
      Xr("AES-OFB", ye.cipher.modes.ofb);
      Xr("AES-CTR", ye.cipher.modes.ctr);
      Xr("AES-GCM", ye.cipher.modes.gcm);

      function Xr(e, t) {
         var a = function() {
            return new ye.aes.Algorithm(e, t)
         };
         ye.cipher.registerAlgorithm(e, a)
      }
      var is = !1,
         jr = 4,
         tt, as, Iu, Tr, Bt;

      function bu() {
         is = !0, Iu = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54];
         for (var e = new Array(256), t = 0; t < 128; ++t) e[t] = t << 1, e[t + 128] = t + 128 << 1 ^ 283;
         tt = new Array(256), as = new Array(256), Tr = new Array(4), Bt = new Array(4);
         for (var t = 0; t < 4; ++t) Tr[t] = new Array(256), Bt[t] = new Array(256);
         for (var a = 0, r = 0, n, i, s, o, u, l, c, t = 0; t < 256; ++t) {
            o = r ^ r << 1 ^ r << 2 ^ r << 3 ^ r << 4, o = o >> 8 ^ o & 255 ^ 99, tt[a] = o, as[o] = a, u = e[o], n = e[a], i = e[n], s = e[i], l = u << 24 ^ o << 16 ^ o << 8 ^ (o ^ u), c = (n ^ i ^ s) << 24 ^ (a ^ s) << 16 ^ (a ^ i ^ s) << 8 ^ (a ^ n ^ s);
            for (var f = 0; f < 4; ++f) Tr[f][a] = l, Bt[f][o] = c, l = l << 24 | l >>> 8, c = c << 24 | c >>> 8;
            a === 0 ? a = r = 1 : (a = n ^ e[e[e[n ^ s]]], r ^= e[e[r]])
         }
      }

      function Au(e, t) {
         for (var a = e.slice(0), r, n = 1, i = a.length, s = i + 6 + 1, o = jr * s, u = i; u < o; ++u) r = a[u - 1], u % i === 0 ? (r = tt[r >>> 16 & 255] << 24 ^ tt[r >>> 8 & 255] << 16 ^ tt[r & 255] << 8 ^ tt[r >>> 24] ^ Iu[n] << 24, n++) : i > 6 && u % i === 4 && (r = tt[r >>> 24] << 24 ^ tt[r >>> 16 & 255] << 16 ^ tt[r >>> 8 & 255] << 8 ^ tt[r & 255]), a[u] = a[u - i] ^ r;
         if (t) {
            var l, c = Bt[0],
               f = Bt[1],
               y = Bt[2],
               g = Bt[3],
               m = a.slice(0);
            o = a.length;
            for (var u = 0, x = o - jr; u < o; u += jr, x -= jr)
               if (u === 0 || u === o - jr) m[u] = a[x], m[u + 1] = a[x + 3], m[u + 2] = a[x + 2], m[u + 3] = a[x + 1];
               else
                  for (var T = 0; T < jr; ++T) l = a[x + T], m[u + (3 & -T)] = c[tt[l >>> 24]] ^ f[tt[l >>> 16 & 255]] ^ y[tt[l >>> 8 & 255]] ^ g[tt[l & 255]];
            a = m
         }
         return a
      }

      function ns(e, t, a, r) {
         var n = e.length / 4 - 1,
            i, s, o, u, l;
         r ? (i = Bt[0], s = Bt[1], o = Bt[2], u = Bt[3], l = as) : (i = Tr[0], s = Tr[1], o = Tr[2], u = Tr[3], l = tt);
         var c, f, y, g, m, x, T;
         c = t[0] ^ e[0], f = t[r ? 3 : 1] ^ e[1], y = t[2] ^ e[2], g = t[r ? 1 : 3] ^ e[3];
         for (var I = 3, A = 1; A < n; ++A) m = i[c >>> 24] ^ s[f >>> 16 & 255] ^ o[y >>> 8 & 255] ^ u[g & 255] ^ e[++I], x = i[f >>> 24] ^ s[y >>> 16 & 255] ^ o[g >>> 8 & 255] ^ u[c & 255] ^ e[++I], T = i[y >>> 24] ^ s[g >>> 16 & 255] ^ o[c >>> 8 & 255] ^ u[f & 255] ^ e[++I], g = i[g >>> 24] ^ s[c >>> 16 & 255] ^ o[f >>> 8 & 255] ^ u[y & 255] ^ e[++I], c = m, f = x, y = T;
         a[0] = l[c >>> 24] << 24 ^ l[f >>> 16 & 255] << 16 ^ l[y >>> 8 & 255] << 8 ^ l[g & 255] ^ e[++I], a[r ? 3 : 1] = l[f >>> 24] << 24 ^ l[y >>> 16 & 255] << 16 ^ l[g >>> 8 & 255] << 8 ^ l[c & 255] ^ e[++I], a[2] = l[y >>> 24] << 24 ^ l[g >>> 16 & 255] << 16 ^ l[c >>> 8 & 255] << 8 ^ l[f & 255] ^ e[++I], a[r ? 1 : 3] = l[g >>> 24] << 24 ^ l[c >>> 16 & 255] << 16 ^ l[f >>> 8 & 255] << 8 ^ l[y & 255] ^ e[++I]
      }

      function Fn(e) {
         e = e || {};
         var t = (e.mode || "CBC").toUpperCase(),
            a = "AES-" + t,
            r;
         e.decrypt ? r = ye.cipher.createDecipher(a, e.key) : r = ye.cipher.createCipher(a, e.key);
         var n = r.start;
         return r.start = function(i, s) {
            var o = null;
            s instanceof ye.util.ByteBuffer && (o = s, s = {}), s = s || {}, s.output = o, s.iv = i, n.call(r, s)
         }, r
      }
   });
   var or = Y((dg, wu) => {
      "use strict";
      var $a = $();
      $a.pki = $a.pki || {};
      var ss = wu.exports = $a.pki.oids = $a.oids = $a.oids || {};

      function _(e, t) {
         ss[e] = t, ss[t] = e
      }

      function le(e, t) {
         ss[e] = t
      }
      _("1.2.840.113549.1.1.1", "rsaEncryption");
      _("1.2.840.113549.1.1.4", "md5WithRSAEncryption");
      _("1.2.840.113549.1.1.5", "sha1WithRSAEncryption");
      _("1.2.840.113549.1.1.7", "RSAES-OAEP");
      _("1.2.840.113549.1.1.8", "mgf1");
      _("1.2.840.113549.1.1.9", "pSpecified");
      _("1.2.840.113549.1.1.10", "RSASSA-PSS");
      _("1.2.840.113549.1.1.11", "sha256WithRSAEncryption");
      _("1.2.840.113549.1.1.12", "sha384WithRSAEncryption");
      _("1.2.840.113549.1.1.13", "sha512WithRSAEncryption");
      _("1.3.101.112", "EdDSA25519");
      _("1.2.840.10040.4.3", "dsa-with-sha1");
      _("1.3.14.3.2.7", "desCBC");
      _("1.3.14.3.2.26", "sha1");
      _("1.3.14.3.2.29", "sha1WithRSASignature");
      _("2.16.840.1.101.3.4.2.1", "sha256");
      _("2.16.840.1.101.3.4.2.2", "sha384");
      _("2.16.840.1.101.3.4.2.3", "sha512");
      _("2.16.840.1.101.3.4.2.4", "sha224");
      _("2.16.840.1.101.3.4.2.5", "sha512-224");
      _("2.16.840.1.101.3.4.2.6", "sha512-256");
      _("1.2.840.113549.2.2", "md2");
      _("1.2.840.113549.2.5", "md5");
      _("1.2.840.113549.1.7.1", "data");
      _("1.2.840.113549.1.7.2", "signedData");
      _("1.2.840.113549.1.7.3", "envelopedData");
      _("1.2.840.113549.1.7.4", "signedAndEnvelopedData");
      _("1.2.840.113549.1.7.5", "digestedData");
      _("1.2.840.113549.1.7.6", "encryptedData");
      _("1.2.840.113549.1.9.1", "emailAddress");
      _("1.2.840.113549.1.9.2", "unstructuredName");
      _("1.2.840.113549.1.9.3", "contentType");
      _("1.2.840.113549.1.9.4", "messageDigest");
      _("1.2.840.113549.1.9.5", "signingTime");
      _("1.2.840.113549.1.9.6", "counterSignature");
      _("1.2.840.113549.1.9.7", "challengePassword");
      _("1.2.840.113549.1.9.8", "unstructuredAddress");
      _("1.2.840.113549.1.9.14", "extensionRequest");
      _("1.2.840.113549.1.9.20", "friendlyName");
      _("1.2.840.113549.1.9.21", "localKeyId");
      _("1.2.840.113549.1.9.22.1", "x509Certificate");
      _("1.2.840.113549.1.12.10.1.1", "keyBag");
      _("1.2.840.113549.1.12.10.1.2", "pkcs8ShroudedKeyBag");
      _("1.2.840.113549.1.12.10.1.3", "certBag");
      _("1.2.840.113549.1.12.10.1.4", "crlBag");
      _("1.2.840.113549.1.12.10.1.5", "secretBag");
      _("1.2.840.113549.1.12.10.1.6", "safeContentsBag");
      _("1.2.840.113549.1.5.13", "pkcs5PBES2");
      _("1.2.840.113549.1.5.12", "pkcs5PBKDF2");
      _("1.2.840.113549.1.12.1.1", "pbeWithSHAAnd128BitRC4");
      _("1.2.840.113549.1.12.1.2", "pbeWithSHAAnd40BitRC4");
      _("1.2.840.113549.1.12.1.3", "pbeWithSHAAnd3-KeyTripleDES-CBC");
      _("1.2.840.113549.1.12.1.4", "pbeWithSHAAnd2-KeyTripleDES-CBC");
      _("1.2.840.113549.1.12.1.5", "pbeWithSHAAnd128BitRC2-CBC");
      _("1.2.840.113549.1.12.1.6", "pbewithSHAAnd40BitRC2-CBC");
      _("1.2.840.113549.2.7", "hmacWithSHA1");
      _("1.2.840.113549.2.8", "hmacWithSHA224");
      _("1.2.840.113549.2.9", "hmacWithSHA256");
      _("1.2.840.113549.2.10", "hmacWithSHA384");
      _("1.2.840.113549.2.11", "hmacWithSHA512");
      _("1.2.840.113549.3.7", "des-EDE3-CBC");
      _("2.16.840.1.101.3.4.1.2", "aes128-CBC");
      _("2.16.840.1.101.3.4.1.22", "aes192-CBC");
      _("2.16.840.1.101.3.4.1.42", "aes256-CBC");
      _("2.5.4.3", "commonName");
      _("2.5.4.4", "surname");
      _("2.5.4.5", "serialNumber");
      _("2.5.4.6", "countryName");
      _("2.5.4.7", "localityName");
      _("2.5.4.8", "stateOrProvinceName");
      _("2.5.4.9", "streetAddress");
      _("2.5.4.10", "organizationName");
      _("2.5.4.11", "organizationalUnitName");
      _("2.5.4.12", "title");
      _("2.5.4.13", "description");
      _("2.5.4.15", "businessCategory");
      _("2.5.4.17", "postalCode");
      _("2.5.4.42", "givenName");
      _("1.3.6.1.4.1.311.60.2.1.2", "jurisdictionOfIncorporationStateOrProvinceName");
      _("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionOfIncorporationCountryName");
      _("2.16.840.1.113730.1.1", "nsCertType");
      _("2.16.840.1.113730.1.13", "nsComment");
      le("2.5.29.1", "authorityKeyIdentifier");
      le("2.5.29.2", "keyAttributes");
      le("2.5.29.3", "certificatePolicies");
      le("2.5.29.4", "keyUsageRestriction");
      le("2.5.29.5", "policyMapping");
      le("2.5.29.6", "subtreesConstraint");
      le("2.5.29.7", "subjectAltName");
      le("2.5.29.8", "issuerAltName");
      le("2.5.29.9", "subjectDirectoryAttributes");
      le("2.5.29.10", "basicConstraints");
      le("2.5.29.11", "nameConstraints");
      le("2.5.29.12", "policyConstraints");
      le("2.5.29.13", "basicConstraints");
      _("2.5.29.14", "subjectKeyIdentifier");
      _("2.5.29.15", "keyUsage");
      le("2.5.29.16", "privateKeyUsagePeriod");
      _("2.5.29.17", "subjectAltName");
      _("2.5.29.18", "issuerAltName");
      _("2.5.29.19", "basicConstraints");
      le("2.5.29.20", "cRLNumber");
      le("2.5.29.21", "cRLReason");
      le("2.5.29.22", "expirationDate");
      le("2.5.29.23", "instructionCode");
      le("2.5.29.24", "invalidityDate");
      le("2.5.29.25", "cRLDistributionPoints");
      le("2.5.29.26", "issuingDistributionPoint");
      le("2.5.29.27", "deltaCRLIndicator");
      le("2.5.29.28", "issuingDistributionPoint");
      le("2.5.29.29", "certificateIssuer");
      le("2.5.29.30", "nameConstraints");
      _("2.5.29.31", "cRLDistributionPoints");
      _("2.5.29.32", "certificatePolicies");
      le("2.5.29.33", "policyMappings");
      le("2.5.29.34", "policyConstraints");
      _("2.5.29.35", "authorityKeyIdentifier");
      le("2.5.29.36", "policyConstraints");
      _("2.5.29.37", "extKeyUsage");
      le("2.5.29.46", "freshestCRL");
      le("2.5.29.54", "inhibitAnyPolicy");
      _("1.3.6.1.4.1.11129.2.4.2", "timestampList");
      _("1.3.6.1.5.5.7.1.1", "authorityInfoAccess");
      _("1.3.6.1.5.5.7.3.1", "serverAuth");
      _("1.3.6.1.5.5.7.3.2", "clientAuth");
      _("1.3.6.1.5.5.7.3.3", "codeSigning");
      _("1.3.6.1.5.5.7.3.4", "emailProtection");
      _("1.3.6.1.5.5.7.3.8", "timeStamping")
   });
   var wt = Y((pg, _u) => {
      "use strict";
      var ve = $();
      ae();
      or();
      var U = _u.exports = ve.asn1 = ve.asn1 || {};
      U.Class = {
         UNIVERSAL: 0,
         APPLICATION: 64,
         CONTEXT_SPECIFIC: 128,
         PRIVATE: 192
      };
      U.Type = {
         NONE: 0,
         BOOLEAN: 1,
         INTEGER: 2,
         BITSTRING: 3,
         OCTETSTRING: 4,
         NULL: 5,
         OID: 6,
         ODESC: 7,
         EXTERNAL: 8,
         REAL: 9,
         ENUMERATED: 10,
         EMBEDDED: 11,
         UTF8: 12,
         ROID: 13,
         SEQUENCE: 16,
         SET: 17,
         PRINTABLESTRING: 19,
         IA5STRING: 22,
         UTCTIME: 23,
         GENERALIZEDTIME: 24,
         BMPSTRING: 30
      };
      U.create = function(e, t, a, r, n) {
         if (ve.util.isArray(r)) {
            for (var i = [], s = 0; s < r.length; ++s) r[s] !== void 0 && i.push(r[s]);
            r = i
         }
         var o = {
            tagClass: e,
            type: t,
            constructed: a,
            composed: a || ve.util.isArray(r),
            value: r
         };
         return n && "bitStringContents" in n && (o.bitStringContents = n.bitStringContents, o.original = U.copy(o)), o
      };
      U.copy = function(e, t) {
         var a;
         if (ve.util.isArray(e)) {
            a = [];
            for (var r = 0; r < e.length; ++r) a.push(U.copy(e[r], t));
            return a
         }
         return typeof e == "string" ? e : (a = {
            tagClass: e.tagClass,
            type: e.type,
            constructed: e.constructed,
            composed: e.composed,
            value: U.copy(e.value, t)
         }, t && !t.excludeBitStringContents && (a.bitStringContents = e.bitStringContents), a)
      };
      U.equals = function(e, t, a) {
         if (ve.util.isArray(e)) {
            if (!ve.util.isArray(t) || e.length !== t.length) return !1;
            for (var r = 0; r < e.length; ++r)
               if (!U.equals(e[r], t[r])) return !1;
            return !0
         }
         if (typeof e != typeof t) return !1;
         if (typeof e == "string") return e === t;
         var n = e.tagClass === t.tagClass && e.type === t.type && e.constructed === t.constructed && e.composed === t.composed && U.equals(e.value, t.value);
         return a && a.includeBitStringContents && (n = n && e.bitStringContents === t.bitStringContents), n
      };
      U.getBerValueLength = function(e) {
         var t = e.getByte();
         if (t !== 128) {
            var a, r = t & 128;
            return r ? a = e.getInt((t & 127) << 3) : a = t, a
         }
      };

      function ja(e, t, a) {
         if (a > t) {
            var r = new Error("Too few bytes to parse DER.");
            throw r.available = e.length(), r.remaining = t, r.requested = a, r
         }
      }
      var S0 = function(e, t) {
         var a = e.getByte();
         if (t--, a !== 128) {
            var r, n = a & 128;
            if (!n) r = a;
            else {
               var i = a & 127;
               ja(e, t, i), r = e.getInt(i << 3)
            }
            if (r < 0) throw new Error("Negative length: " + r);
            return r
         }
      };
      U.fromDer = function(e, t) {
         t === void 0 && (t = {
            strict: !0,
            parseAllBytes: !0,
            decodeBitStrings: !0
         }), typeof t == "boolean" && (t = {
            strict: t,
            parseAllBytes: !0,
            decodeBitStrings: !0
         }), "strict" in t || (t.strict = !0), "parseAllBytes" in t || (t.parseAllBytes = !0), "decodeBitStrings" in t || (t.decodeBitStrings = !0), typeof e == "string" && (e = ve.util.createBuffer(e));
         var a = e.length(),
            r = Pn(e, e.length(), 0, t);
         if (t.parseAllBytes && e.length() !== 0) {
            var n = new Error("Unparsed DER bytes remain after ASN.1 parsing.");
            throw n.byteCount = a, n.remaining = e.length(), n
         }
         return r
      };

      function Pn(e, t, a, r) {
         var n;
         ja(e, t, 2);
         var i = e.getByte();
         t--;
         var s = i & 192,
            o = i & 31;
         n = e.length();
         var u = S0(e, t);
         if (t -= n - e.length(), u !== void 0 && u > t) {
            if (r.strict) {
               var l = new Error("Too few bytes to read ASN.1 value.");
               throw l.available = e.length(), l.remaining = t, l.requested = u, l
            }
            u = t
         }
         var c, f, y = (i & 32) === 32;
         if (y)
            if (c = [], u === void 0)
               for (;;) {
                  if (ja(e, t, 2), e.bytes(2) === String.fromCharCode(0, 0)) {
                     e.getBytes(2), t -= 2;
                     break
                  }
                  n = e.length(), c.push(Pn(e, t, a + 1, r)), t -= n - e.length()
               } else
                  for (; u > 0;) n = e.length(), c.push(Pn(e, u, a + 1, r)), t -= n - e.length(), u -= n - e.length();
         if (c === void 0 && s === U.Class.UNIVERSAL && o === U.Type.BITSTRING && (f = e.bytes(u)), c === void 0 && r.decodeBitStrings && s === U.Class.UNIVERSAL && o === U.Type.BITSTRING && u > 1) {
            var g = e.read,
               m = t,
               x = 0;
            if (o === U.Type.BITSTRING && (ja(e, t, 1), x = e.getByte(), t--), x === 0) try {
               n = e.length();
               var T = {
                     strict: !0,
                     decodeBitStrings: !0
                  },
                  I = Pn(e, t, a + 1, T),
                  A = n - e.length();
               t -= A, o == U.Type.BITSTRING && A++;
               var B = I.tagClass;
               A === u && (B === U.Class.UNIVERSAL || B === U.Class.CONTEXT_SPECIFIC) && (c = [I])
            } catch {}
            c === void 0 && (e.read = g, t = m)
         }
         if (c === void 0) {
            if (u === void 0) {
               if (r.strict) throw new Error("Non-constructed ASN.1 object of indefinite length.");
               u = t
            }
            if (o === U.Type.BMPSTRING)
               for (c = ""; u > 0; u -= 2) ja(e, t, 2), c += String.fromCharCode(e.getInt16()), t -= 2;
            else c = e.getBytes(u), t -= u
         }
         var F = f === void 0 ? null : {
            bitStringContents: f
         };
         return U.create(s, o, y, c, F)
      }
      U.toDer = function(e) {
         var t = ve.util.createBuffer(),
            a = e.tagClass | e.type,
            r = ve.util.createBuffer(),
            n = !1;
         if ("bitStringContents" in e && (n = !0, e.original && (n = U.equals(e, e.original))), n) r.putBytes(e.bitStringContents);
         else if (e.composed) {
            e.constructed ? a |= 32 : r.putByte(0);
            for (var i = 0; i < e.value.length; ++i) e.value[i] !== void 0 && r.putBuffer(U.toDer(e.value[i]))
         } else if (e.type === U.Type.BMPSTRING)
            for (var i = 0; i < e.value.length; ++i) r.putInt16(e.value.charCodeAt(i));
         else e.type === U.Type.INTEGER && e.value.length > 1 && (e.value.charCodeAt(0) === 0 && !(e.value.charCodeAt(1) & 128) || e.value.charCodeAt(0) === 255 && (e.value.charCodeAt(1) & 128) === 128) ? r.putBytes(e.value.substr(1)) : r.putBytes(e.value);
         if (t.putByte(a), r.length() <= 127) t.putByte(r.length() & 127);
         else {
            var s = r.length(),
               o = "";
            do o += String.fromCharCode(s & 255), s = s >>> 8; while (s > 0);
            t.putByte(o.length | 128);
            for (var i = o.length - 1; i >= 0; --i) t.putByte(o.charCodeAt(i))
         }
         return t.putBuffer(r), t
      };
      U.oidToDer = function(e) {
         var t = e.split("."),
            a = ve.util.createBuffer();
         a.putByte(40 * parseInt(t[0], 10) + parseInt(t[1], 10));
         for (var r, n, i, s, o = 2; o < t.length; ++o) {
            r = !0, n = [], i = parseInt(t[o], 10);
            do s = i & 127, i = i >>> 7, r || (s |= 128), n.push(s), r = !1; while (i > 0);
            for (var u = n.length - 1; u >= 0; --u) a.putByte(n[u])
         }
         return a
      };
      U.derToOid = function(e) {
         var t;
         typeof e == "string" && (e = ve.util.createBuffer(e));
         var a = e.getByte();
         t = Math.floor(a / 40) + "." + a % 40;
         for (var r = 0; e.length() > 0;) a = e.getByte(), r = r << 7, a & 128 ? r += a & 127 : (t += "." + (r + a), r = 0);
         return t
      };
      U.utcTimeToDate = function(e) {
         var t = new Date,
            a = parseInt(e.substr(0, 2), 10);
         a = a >= 50 ? 1900 + a : 2e3 + a;
         var r = parseInt(e.substr(2, 2), 10) - 1,
            n = parseInt(e.substr(4, 2), 10),
            i = parseInt(e.substr(6, 2), 10),
            s = parseInt(e.substr(8, 2), 10),
            o = 0;
         if (e.length > 11) {
            var u = e.charAt(10),
               l = 10;
            u !== "+" && u !== "-" && (o = parseInt(e.substr(10, 2), 10), l += 2)
         }
         if (t.setUTCFullYear(a, r, n), t.setUTCHours(i, s, o, 0), l && (u = e.charAt(l), u === "+" || u === "-")) {
            var c = parseInt(e.substr(l + 1, 2), 10),
               f = parseInt(e.substr(l + 4, 2), 10),
               y = c * 60 + f;
            y *= 6e4, u === "+" ? t.setTime(+t - y) : t.setTime(+t + y)
         }
         return t
      };
      U.generalizedTimeToDate = function(e) {
         var t = new Date,
            a = parseInt(e.substr(0, 4), 10),
            r = parseInt(e.substr(4, 2), 10) - 1,
            n = parseInt(e.substr(6, 2), 10),
            i = parseInt(e.substr(8, 2), 10),
            s = parseInt(e.substr(10, 2), 10),
            o = parseInt(e.substr(12, 2), 10),
            u = 0,
            l = 0,
            c = !1;
         e.charAt(e.length - 1) === "Z" && (c = !0);
         var f = e.length - 5,
            y = e.charAt(f);
         if (y === "+" || y === "-") {
            var g = parseInt(e.substr(f + 1, 2), 10),
               m = parseInt(e.substr(f + 4, 2), 10);
            l = g * 60 + m, l *= 6e4, y === "+" && (l *= -1), c = !0
         }
         return e.charAt(14) === "." && (u = parseFloat(e.substr(14), 10) * 1e3), c ? (t.setUTCFullYear(a, r, n), t.setUTCHours(i, s, o, u), t.setTime(+t + l)) : (t.setFullYear(a, r, n), t.setHours(i, s, o, u)), t
      };
      U.dateToUtcTime = function(e) {
         if (typeof e == "string") return e;
         var t = "",
            a = [];
         a.push(("" + e.getUTCFullYear()).substr(2)), a.push("" + (e.getUTCMonth() + 1)), a.push("" + e.getUTCDate()), a.push("" + e.getUTCHours()), a.push("" + e.getUTCMinutes()), a.push("" + e.getUTCSeconds());
         for (var r = 0; r < a.length; ++r) a[r].length < 2 && (t += "0"), t += a[r];
         return t += "Z", t
      };
      U.dateToGeneralizedTime = function(e) {
         if (typeof e == "string") return e;
         var t = "",
            a = [];
         a.push("" + e.getUTCFullYear()), a.push("" + (e.getUTCMonth() + 1)), a.push("" + e.getUTCDate()), a.push("" + e.getUTCHours()), a.push("" + e.getUTCMinutes()), a.push("" + e.getUTCSeconds());
         for (var r = 0; r < a.length; ++r) a[r].length < 2 && (t += "0"), t += a[r];
         return t += "Z", t
      };
      U.integerToDer = function(e) {
         var t = ve.util.createBuffer();
         if (e >= -128 && e < 128) return t.putSignedInt(e, 8);
         if (e >= -32768 && e < 32768) return t.putSignedInt(e, 16);
         if (e >= -8388608 && e < 8388608) return t.putSignedInt(e, 24);
         if (e >= -2147483648 && e < 2147483648) return t.putSignedInt(e, 32);
         var a = new Error("Integer too large; max is 32-bits.");
         throw a.integer = e, a
      };
      U.derToInteger = function(e) {
         typeof e == "string" && (e = ve.util.createBuffer(e));
         var t = e.length() * 8;
         if (t > 32) throw new Error("Integer too large; max is 32-bits.");
         return e.getSignedInt(t)
      };
      U.validate = function(e, t, a, r) {
         var n = !1;
         if ((e.tagClass === t.tagClass || typeof t.tagClass > "u") && (e.type === t.type || typeof t.type > "u"))
            if (e.constructed === t.constructed || typeof t.constructed > "u") {
               if (n = !0, t.value && ve.util.isArray(t.value))
                  for (var i = 0, s = 0; n && s < t.value.length; ++s) n = t.value[s].optional || !1, e.value[i] && (n = U.validate(e.value[i], t.value[s], a, r), n ? ++i : t.value[s].optional && (n = !0)), !n && r && r.push("[" + t.name + '] Tag class "' + t.tagClass + '", type "' + t.type + '" expected value length "' + t.value.length + '", got "' + e.value.length + '"');
               if (n && a && (t.capture && (a[t.capture] = e.value), t.captureAsn1 && (a[t.captureAsn1] = e), t.captureBitStringContents && "bitStringContents" in e && (a[t.captureBitStringContents] = e.bitStringContents), t.captureBitStringValue && "bitStringContents" in e)) {
                  var o;
                  if (e.bitStringContents.length < 2) a[t.captureBitStringValue] = "";
                  else {
                     var u = e.bitStringContents.charCodeAt(0);
                     if (u !== 0) throw new Error("captureBitStringValue only supported for zero unused bits");
                     a[t.captureBitStringValue] = e.bitStringContents.slice(1)
                  }
               }
            } else r && r.push("[" + t.name + '] Expected constructed "' + t.constructed + '", got "' + e.constructed + '"');
         else r && (e.tagClass !== t.tagClass && r.push("[" + t.name + '] Expected tag class "' + t.tagClass + '", got "' + e.tagClass + '"'), e.type !== t.type && r.push("[" + t.name + '] Expected type "' + t.type + '", got "' + e.type + '"'));
         return n
      };
      var Nu = /[^\\u0000-\\u00ff]/;
      U.prettyPrint = function(e, t, a) {
         var r = "";
         t = t || 0, a = a || 2, t > 0 && (r += `
`);
         for (var n = "", i = 0; i < t * a; ++i) n += " ";
         switch (r += n + "Tag: ", e.tagClass) {
            case U.Class.UNIVERSAL:
               r += "Universal:";
               break;
            case U.Class.APPLICATION:
               r += "Application:";
               break;
            case U.Class.CONTEXT_SPECIFIC:
               r += "Context-Specific:";
               break;
            case U.Class.PRIVATE:
               r += "Private:";
               break
         }
         if (e.tagClass === U.Class.UNIVERSAL) switch (r += e.type, e.type) {
            case U.Type.NONE:
               r += " (None)";
               break;
            case U.Type.BOOLEAN:
               r += " (Boolean)";
               break;
            case U.Type.INTEGER:
               r += " (Integer)";
               break;
            case U.Type.BITSTRING:
               r += " (Bit string)";
               break;
            case U.Type.OCTETSTRING:
               r += " (Octet string)";
               break;
            case U.Type.NULL:
               r += " (Null)";
               break;
            case U.Type.OID:
               r += " (Object Identifier)";
               break;
            case U.Type.ODESC:
               r += " (Object Descriptor)";
               break;
            case U.Type.EXTERNAL:
               r += " (External or Instance of)";
               break;
            case U.Type.REAL:
               r += " (Real)";
               break;
            case U.Type.ENUMERATED:
               r += " (Enumerated)";
               break;
            case U.Type.EMBEDDED:
               r += " (Embedded PDV)";
               break;
            case U.Type.UTF8:
               r += " (UTF8)";
               break;
            case U.Type.ROID:
               r += " (Relative Object Identifier)";
               break;
            case U.Type.SEQUENCE:
               r += " (Sequence)";
               break;
            case U.Type.SET:
               r += " (Set)";
               break;
            case U.Type.PRINTABLESTRING:
               r += " (Printable String)";
               break;
            case U.Type.IA5String:
               r += " (IA5String (ASCII))";
               break;
            case U.Type.UTCTIME:
               r += " (UTC time)";
               break;
            case U.Type.GENERALIZEDTIME:
               r += " (Generalized time)";
               break;
            case U.Type.BMPSTRING:
               r += " (BMP String)";
               break
         } else r += e.type;
         if (r += `
`, r += n + "Constructed: " + e.constructed + `
`, e.composed) {
            for (var s = 0, o = "", i = 0; i < e.value.length; ++i) e.value[i] !== void 0 && (s += 1, o += U.prettyPrint(e.value[i], t + 1, a), i + 1 < e.value.length && (o += ","));
            r += n + "Sub values: " + s + o
         } else {
            if (r += n + "Value: ", e.type === U.Type.OID) {
               var u = U.derToOid(e.value);
               r += u, ve.pki && ve.pki.oids && u in ve.pki.oids && (r += " (" + ve.pki.oids[u] + ") ")
            }
            if (e.type === U.Type.INTEGER) try {
               r += U.derToInteger(e.value)
            } catch {
               r += "0x" + ve.util.bytesToHex(e.value)
            } else if (e.type === U.Type.BITSTRING) {
               if (e.value.length > 1 ? r += "0x" + ve.util.bytesToHex(e.value.slice(1)) : r += "(none)", e.value.length > 0) {
                  var l = e.value.charCodeAt(0);
                  l == 1 ? r += " (1 unused bit shown)" : l > 1 && (r += " (" + l + " unused bits shown)")
               }
            } else if (e.type === U.Type.OCTETSTRING) Nu.test(e.value) || (r += "(" + e.value + ") "), r += "0x" + ve.util.bytesToHex(e.value);
            else if (e.type === U.Type.UTF8) try {
               r += ve.util.decodeUtf8(e.value)
            } catch (c) {
               if (c.message === "URI malformed") r += "0x" + ve.util.bytesToHex(e.value) + " (malformed UTF8)";
               else throw c
            } else e.type === U.Type.PRINTABLESTRING || e.type === U.Type.IA5String ? r += e.value : Nu.test(e.value) ? r += "0x" + ve.util.bytesToHex(e.value) : e.value.length === 0 ? r += "[null]" : r += e.value
         }
         return r
      }
   });
   var Rt = Y((yg, Du) => {
      "use strict";
      var Vn = $();
      Du.exports = Vn.md = Vn.md || {};
      Vn.md.algorithms = Vn.md.algorithms || {}
   });
   var Jr = Y((mg, Ru) => {
      "use strict";
      var Yt = $();
      Rt();
      ae();
      var I0 = Ru.exports = Yt.hmac = Yt.hmac || {};
      I0.create = function() {
         var e = null,
            t = null,
            a = null,
            r = null,
            n = {};
         return n.start = function(i, s) {
            if (i !== null)
               if (typeof i == "string")
                  if (i = i.toLowerCase(), i in Yt.md.algorithms) t = Yt.md.algorithms[i].create();
                  else throw new Error('Unknown hash algorithm "' + i + '"');
            else t = i;
            if (s === null) s = e;
            else {
               if (typeof s == "string") s = Yt.util.createBuffer(s);
               else if (Yt.util.isArray(s)) {
                  var o = s;
                  s = Yt.util.createBuffer();
                  for (var u = 0; u < o.length; ++u) s.putByte(o[u])
               }
               var l = s.length();
               l > t.blockLength && (t.start(), t.update(s.bytes()), s = t.digest()), a = Yt.util.createBuffer(), r = Yt.util.createBuffer(), l = s.length();
               for (var u = 0; u < l; ++u) {
                  var o = s.at(u);
                  a.putByte(54 ^ o), r.putByte(92 ^ o)
               }
               if (l < t.blockLength)
                  for (var o = t.blockLength - l, u = 0; u < o; ++u) a.putByte(54), r.putByte(92);
               e = s, a = a.bytes(), r = r.bytes()
            }
            t.start(), t.update(a)
         }, n.update = function(i) {
            t.update(i)
         }, n.getMac = function() {
            var i = t.digest().bytes();
            return t.start(), t.update(r), t.update(i), t.digest()
         }, n.digest = n.getMac, n
      }
   });
   var Kn = Y((gg, Uu) => {
      "use strict";
      var Lt = $();
      Rt();
      ae();
      var ku = Uu.exports = Lt.md5 = Lt.md5 || {};
      Lt.md.md5 = Lt.md.algorithms.md5 = ku;
      ku.create = function() {
         Ou || b0();
         var e = null,
            t = Lt.util.createBuffer(),
            a = new Array(16),
            r = {
               algorithm: "md5",
               blockLength: 64,
               digestLength: 16,
               messageLength: 0,
               fullMessageLength: null,
               messageLengthSize: 8
            };
         return r.start = function() {
            r.messageLength = 0, r.fullMessageLength = r.messageLength64 = [];
            for (var n = r.messageLengthSize / 4, i = 0; i < n; ++i) r.fullMessageLength.push(0);
            return t = Lt.util.createBuffer(), e = {
               h0: 1732584193,
               h1: 4023233417,
               h2: 2562383102,
               h3: 271733878
            }, r
         }, r.start(), r.update = function(n, i) {
            i === "utf8" && (n = Lt.util.encodeUtf8(n));
            var s = n.length;
            r.messageLength += s, s = [s / 4294967296 >>> 0, s >>> 0];
            for (var o = r.fullMessageLength.length - 1; o >= 0; --o) r.fullMessageLength[o] += s[1], s[1] = s[0] + (r.fullMessageLength[o] / 4294967296 >>> 0), r.fullMessageLength[o] = r.fullMessageLength[o] >>> 0, s[0] = s[1] / 4294967296 >>> 0;
            return t.putBytes(n), Lu(e, a, t), (t.read > 2048 || t.length() === 0) && t.compact(), r
         }, r.digest = function() {
            var n = Lt.util.createBuffer();
            n.putBytes(t.bytes());
            var i = r.fullMessageLength[r.fullMessageLength.length - 1] + r.messageLengthSize,
               s = i & r.blockLength - 1;
            n.putBytes(os.substr(0, r.blockLength - s));
            for (var o, u = 0, l = r.fullMessageLength.length - 1; l >= 0; --l) o = r.fullMessageLength[l] * 8 + u, u = o / 4294967296 >>> 0, n.putInt32Le(o >>> 0);
            var c = {
               h0: e.h0,
               h1: e.h1,
               h2: e.h2,
               h3: e.h3
            };
            Lu(c, a, n);
            var f = Lt.util.createBuffer();
            return f.putInt32Le(c.h0), f.putInt32Le(c.h1), f.putInt32Le(c.h2), f.putInt32Le(c.h3), f
         }, r
      };
      var os = null,
         Mn = null,
         Xa = null,
         ea = null,
         Ou = !1;

      function b0() {
         os = String.fromCharCode(128), os += Lt.util.fillString(String.fromCharCode(0), 64), Mn = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9], Xa = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21], ea = new Array(64);
         for (var e = 0; e < 64; ++e) ea[e] = Math.floor(Math.abs(Math.sin(e + 1)) * 4294967296);
         Ou = !0
      }

      function Lu(e, t, a) {
         for (var r, n, i, s, o, u, l, c, f = a.length(); f >= 64;) {
            for (n = e.h0, i = e.h1, s = e.h2, o = e.h3, c = 0; c < 16; ++c) t[c] = a.getInt32Le(), u = o ^ i & (s ^ o), r = n + u + ea[c] + t[c], l = Xa[c], n = o, o = s, s = i, i += r << l | r >>> 32 - l;
            for (; c < 32; ++c) u = s ^ o & (i ^ s), r = n + u + ea[c] + t[Mn[c]], l = Xa[c], n = o, o = s, s = i, i += r << l | r >>> 32 - l;
            for (; c < 48; ++c) u = i ^ s ^ o, r = n + u + ea[c] + t[Mn[c]], l = Xa[c], n = o, o = s, s = i, i += r << l | r >>> 32 - l;
            for (; c < 64; ++c) u = s ^ (i | ~o), r = n + u + ea[c] + t[Mn[c]], l = Xa[c], n = o, o = s, s = i, i += r << l | r >>> 32 - l;
            e.h0 = e.h0 + n | 0, e.h1 = e.h1 + i | 0, e.h2 = e.h2 + s | 0, e.h3 = e.h3 + o | 0, f -= 64
         }
      }
   });
   var Sr = Y((vg, Pu) => {
      "use strict";
      var Hn = $();
      ae();
      var Fu = Pu.exports = Hn.pem = Hn.pem || {};
      Fu.encode = function(e, t) {
         t = t || {};
         var a = "-----BEGIN " + e.type + `-----\r
`,
            r;
         if (e.procType && (r = {
               name: "Proc-Type",
               values: [String(e.procType.version), e.procType.type]
            }, a += qn(r)), e.contentDomain && (r = {
               name: "Content-Domain",
               values: [e.contentDomain]
            }, a += qn(r)), e.dekInfo && (r = {
               name: "DEK-Info",
               values: [e.dekInfo.algorithm]
            }, e.dekInfo.parameters && r.values.push(e.dekInfo.parameters), a += qn(r)), e.headers)
            for (var n = 0; n < e.headers.length; ++n) a += qn(e.headers[n]);
         return e.procType && (a += `\r
`), a += Hn.util.encode64(e.body, t.maxline || 64) + `\r
`, a += "-----END " + e.type + `-----\r
`, a
      };
      Fu.decode = function(e) {
         for (var t = [], a = /\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\x21-\x7e\s]+?(?:\r?\n\r?\n))?([:A-Za-z0-9+\/=\s]+?)-----END \1-----/g, r = /([\x21-\x7e]+):\s*([\x21-\x7e\s^:]+)/, n = /\r?\n/, i; i = a.exec(e), !!i;) {
            var s = i[1];
            s === "NEW CERTIFICATE REQUEST" && (s = "CERTIFICATE REQUEST");
            var o = {
               type: s,
               procType: null,
               contentDomain: null,
               dekInfo: null,
               headers: [],
               body: Hn.util.decode64(i[3])
            };
            if (t.push(o), !!i[2]) {
               for (var u = i[2].split(n), l = 0; i && l < u.length;) {
                  for (var c = u[l].replace(/\s+$/, ""), f = l + 1; f < u.length; ++f) {
                     var y = u[f];
                     if (!/\s/.test(y[0])) break;
                     c += y, l = f
                  }
                  if (i = c.match(r), i) {
                     for (var g = {
                           name: i[1],
                           values: []
                        }, m = i[2].split(","), x = 0; x < m.length; ++x) g.values.push(A0(m[x]));
                     if (o.procType)
                        if (!o.contentDomain && g.name === "Content-Domain") o.contentDomain = m[0] || "";
                        else if (!o.dekInfo && g.name === "DEK-Info") {
                        if (g.values.length === 0) throw new Error('Invalid PEM formatted message. The "DEK-Info" header must have at least one subfield.');
                        o.dekInfo = {
                           algorithm: m[0],
                           parameters: m[1] || null
                        }
                     } else o.headers.push(g);
                     else {
                        if (g.name !== "Proc-Type") throw new Error('Invalid PEM formatted message. The first encapsulated header must be "Proc-Type".');
                        if (g.values.length !== 2) throw new Error('Invalid PEM formatted message. The "Proc-Type" header must have two subfields.');
                        o.procType = {
                           version: m[0],
                           type: m[1]
                        }
                     }
                  }++l
               }
               if (o.procType === "ENCRYPTED" && !o.dekInfo) throw new Error('Invalid PEM formatted message. The "DEK-Info" header must be present if "Proc-Type" is "ENCRYPTED".')
            }
         }
         if (t.length === 0) throw new Error("Invalid PEM formatted message.");
         return t
      };

      function qn(e) {
         for (var t = e.name + ": ", a = [], r = function(u, l) {
               return " " + l
            }, n = 0; n < e.values.length; ++n) a.push(e.values[n].replace(/^(\S+\r\n)/, r));
         t += a.join(",") + `\r
`;
         for (var i = 0, s = -1, n = 0; n < t.length; ++n, ++i)
            if (i > 65 && s !== -1) {
               var o = t[s];
               o === "," ? (++s, t = t.substr(0, s) + `\r
 ` + t.substr(s)) : t = t.substr(0, s) + `\r
` + o + t.substr(s + 1), i = n - s - 1, s = -1, ++n
            } else(t[n] === " " || t[n] === "	" || t[n] === ",") && (s = n);
         return t
      }

      function A0(e) {
         return e.replace(/^\s+/, "")
      }
   });
   var Ja = Y((Eg, Mu) => {
      "use strict";
      var Ce = $();
      kn();
      rs();
      ae();
      Mu.exports = Ce.des = Ce.des || {};
      Ce.des.startEncrypting = function(e, t, a, r) {
         var n = Gn({
            key: e,
            output: a,
            decrypt: !1,
            mode: r || (t === null ? "ECB" : "CBC")
         });
         return n.start(t), n
      };
      Ce.des.createEncryptionCipher = function(e, t) {
         return Gn({
            key: e,
            output: null,
            decrypt: !1,
            mode: t
         })
      };
      Ce.des.startDecrypting = function(e, t, a, r) {
         var n = Gn({
            key: e,
            output: a,
            decrypt: !0,
            mode: r || (t === null ? "ECB" : "CBC")
         });
         return n.start(t), n
      };
      Ce.des.createDecryptionCipher = function(e, t) {
         return Gn({
            key: e,
            output: null,
            decrypt: !0,
            mode: t
         })
      };
      Ce.des.Algorithm = function(e, t) {
         var a = this;
         a.name = e, a.mode = new t({
            blockSize: 8,
            cipher: {
               encrypt: function(r, n) {
                  return Vu(a._keys, r, n, !1)
               },
               decrypt: function(r, n) {
                  return Vu(a._keys, r, n, !0)
               }
            }
         }), a._init = !1
      };
      Ce.des.Algorithm.prototype.initialize = function(e) {
         if (!this._init) {
            var t = Ce.util.createBuffer(e.key);
            if (this.name.indexOf("3DES") === 0 && t.length() !== 24) throw new Error("Invalid Triple-DES key size: " + t.length() * 8);
            this._keys = O0(t), this._init = !0
         }
      };
      kt("DES-ECB", Ce.cipher.modes.ecb);
      kt("DES-CBC", Ce.cipher.modes.cbc);
      kt("DES-CFB", Ce.cipher.modes.cfb);
      kt("DES-OFB", Ce.cipher.modes.ofb);
      kt("DES-CTR", Ce.cipher.modes.ctr);
      kt("3DES-ECB", Ce.cipher.modes.ecb);
      kt("3DES-CBC", Ce.cipher.modes.cbc);
      kt("3DES-CFB", Ce.cipher.modes.cfb);
      kt("3DES-OFB", Ce.cipher.modes.ofb);
      kt("3DES-CTR", Ce.cipher.modes.ctr);

      function kt(e, t) {
         var a = function() {
            return new Ce.des.Algorithm(e, t)
         };
         Ce.cipher.registerAlgorithm(e, a)
      }
      var B0 = [16843776, 0, 65536, 16843780, 16842756, 66564, 4, 65536, 1024, 16843776, 16843780, 1024, 16778244, 16842756, 16777216, 4, 1028, 16778240, 16778240, 66560, 66560, 16842752, 16842752, 16778244, 65540, 16777220, 16777220, 65540, 0, 1028, 66564, 16777216, 65536, 16843780, 4, 16842752, 16843776, 16777216, 16777216, 1024, 16842756, 65536, 66560, 16777220, 1024, 4, 16778244, 66564, 16843780, 65540, 16842752, 16778244, 16777220, 1028, 66564, 16843776, 1028, 16778240, 16778240, 0, 65540, 66560, 0, 16842756],
         w0 = [-2146402272, -2147450880, 32768, 1081376, 1048576, 32, -2146435040, -2147450848, -2147483616, -2146402272, -2146402304, -2147483648, -2147450880, 1048576, 32, -2146435040, 1081344, 1048608, -2147450848, 0, -2147483648, 32768, 1081376, -2146435072, 1048608, -2147483616, 0, 1081344, 32800, -2146402304, -2146435072, 32800, 0, 1081376, -2146435040, 1048576, -2147450848, -2146435072, -2146402304, 32768, -2146435072, -2147450880, 32, -2146402272, 1081376, 32, 32768, -2147483648, 32800, -2146402304, 1048576, -2147483616, 1048608, -2147450848, -2147483616, 1048608, 1081344, 0, -2147450880, 32800, -2147483648, -2146435040, -2146402272, 1081344],
         N0 = [520, 134349312, 0, 134348808, 134218240, 0, 131592, 134218240, 131080, 134217736, 134217736, 131072, 134349320, 131080, 134348800, 520, 134217728, 8, 134349312, 512, 131584, 134348800, 134348808, 131592, 134218248, 131584, 131072, 134218248, 8, 134349320, 512, 134217728, 134349312, 134217728, 131080, 520, 131072, 134349312, 134218240, 0, 512, 131080, 134349320, 134218240, 134217736, 512, 0, 134348808, 134218248, 131072, 134217728, 134349320, 8, 131592, 131584, 134217736, 134348800, 134218248, 520, 134348800, 131592, 8, 134348808, 131584],
         _0 = [8396801, 8321, 8321, 128, 8396928, 8388737, 8388609, 8193, 0, 8396800, 8396800, 8396929, 129, 0, 8388736, 8388609, 1, 8192, 8388608, 8396801, 128, 8388608, 8193, 8320, 8388737, 1, 8320, 8388736, 8192, 8396928, 8396929, 129, 8388736, 8388609, 8396800, 8396929, 129, 0, 0, 8396800, 8320, 8388736, 8388737, 1, 8396801, 8321, 8321, 128, 8396929, 129, 1, 8192, 8388609, 8193, 8396928, 8388737, 8193, 8320, 8388608, 8396801, 128, 8388608, 8192, 8396928],
         D0 = [256, 34078976, 34078720, 1107296512, 524288, 256, 1073741824, 34078720, 1074266368, 524288, 33554688, 1074266368, 1107296512, 1107820544, 524544, 1073741824, 33554432, 1074266112, 1074266112, 0, 1073742080, 1107820800, 1107820800, 33554688, 1107820544, 1073742080, 0, 1107296256, 34078976, 33554432, 1107296256, 524544, 524288, 1107296512, 256, 33554432, 1073741824, 34078720, 1107296512, 1074266368, 33554688, 1073741824, 1107820544, 34078976, 1074266368, 256, 33554432, 1107820544, 1107820800, 524544, 1107296256, 1107820800, 34078720, 0, 1074266112, 1107296256, 524544, 33554688, 1073742080, 524288, 0, 1074266112, 34078976, 1073742080],
         R0 = [536870928, 541065216, 16384, 541081616, 541065216, 16, 541081616, 4194304, 536887296, 4210704, 4194304, 536870928, 4194320, 536887296, 536870912, 16400, 0, 4194320, 536887312, 16384, 4210688, 536887312, 16, 541065232, 541065232, 0, 4210704, 541081600, 16400, 4210688, 541081600, 536870912, 536887296, 16, 541065232, 4210688, 541081616, 4194304, 16400, 536870928, 4194304, 536887296, 536870912, 16400, 536870928, 541081616, 4210688, 541065216, 4210704, 541081600, 0, 541065232, 16, 16384, 541065216, 4210704, 16384, 4194320, 536887312, 0, 541081600, 536870912, 4194320, 536887312],
         L0 = [2097152, 69206018, 67110914, 0, 2048, 67110914, 2099202, 69208064, 69208066, 2097152, 0, 67108866, 2, 67108864, 69206018, 2050, 67110912, 2099202, 2097154, 67110912, 67108866, 69206016, 69208064, 2097154, 69206016, 2048, 2050, 69208066, 2099200, 2, 67108864, 2099200, 67108864, 2099200, 2097152, 67110914, 67110914, 69206018, 69206018, 2, 2097154, 67108864, 67110912, 2097152, 69208064, 2050, 2099202, 69208064, 2050, 67108866, 69208066, 69206016, 2099200, 0, 2, 69208066, 0, 2099202, 69206016, 2048, 67108866, 67110912, 2048, 2097154],
         k0 = [268439616, 4096, 262144, 268701760, 268435456, 268439616, 64, 268435456, 262208, 268697600, 268701760, 266240, 268701696, 266304, 4096, 64, 268697600, 268435520, 268439552, 4160, 266240, 262208, 268697664, 268701696, 4160, 0, 0, 268697664, 268435520, 268439552, 266304, 262144, 266304, 262144, 268701696, 4096, 64, 268697664, 4096, 266304, 268439552, 64, 268435520, 268697600, 268697664, 268435456, 262144, 268439616, 0, 268701760, 262208, 268435520, 268697600, 268439552, 268439616, 0, 268701760, 266240, 266240, 4160, 4160, 262208, 268435456, 268701696];

      function O0(e) {
         for (var t = [0, 4, 536870912, 536870916, 65536, 65540, 536936448, 536936452, 512, 516, 536871424, 536871428, 66048, 66052, 536936960, 536936964], a = [0, 1, 1048576, 1048577, 67108864, 67108865, 68157440, 68157441, 256, 257, 1048832, 1048833, 67109120, 67109121, 68157696, 68157697], r = [0, 8, 2048, 2056, 16777216, 16777224, 16779264, 16779272, 0, 8, 2048, 2056, 16777216, 16777224, 16779264, 16779272], n = [0, 2097152, 134217728, 136314880, 8192, 2105344, 134225920, 136323072, 131072, 2228224, 134348800, 136445952, 139264, 2236416, 134356992, 136454144], i = [0, 262144, 16, 262160, 0, 262144, 16, 262160, 4096, 266240, 4112, 266256, 4096, 266240, 4112, 266256], s = [0, 1024, 32, 1056, 0, 1024, 32, 1056, 33554432, 33555456, 33554464, 33555488, 33554432, 33555456, 33554464, 33555488], o = [0, 268435456, 524288, 268959744, 2, 268435458, 524290, 268959746, 0, 268435456, 524288, 268959744, 2, 268435458, 524290, 268959746], u = [0, 65536, 2048, 67584, 536870912, 536936448, 536872960, 536938496, 131072, 196608, 133120, 198656, 537001984, 537067520, 537004032, 537069568], l = [0, 262144, 0, 262144, 2, 262146, 2, 262146, 33554432, 33816576, 33554432, 33816576, 33554434, 33816578, 33554434, 33816578], c = [0, 268435456, 8, 268435464, 0, 268435456, 8, 268435464, 1024, 268436480, 1032, 268436488, 1024, 268436480, 1032, 268436488], f = [0, 32, 0, 32, 1048576, 1048608, 1048576, 1048608, 8192, 8224, 8192, 8224, 1056768, 1056800, 1056768, 1056800], y = [0, 16777216, 512, 16777728, 2097152, 18874368, 2097664, 18874880, 67108864, 83886080, 67109376, 83886592, 69206016, 85983232, 69206528, 85983744], g = [0, 4096, 134217728, 134221824, 524288, 528384, 134742016, 134746112, 16, 4112, 134217744, 134221840, 524304, 528400, 134742032, 134746128], m = [0, 4, 256, 260, 0, 4, 256, 260, 1, 5, 257, 261, 1, 5, 257, 261], x = e.length() > 8 ? 3 : 1, T = [], I = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0], A = 0, B, F = 0; F < x; F++) {
            var R = e.getInt32(),
               D = e.getInt32();
            B = (R >>> 4 ^ D) & 252645135, D ^= B, R ^= B << 4, B = (D >>> -16 ^ R) & 65535, R ^= B, D ^= B << -16, B = (R >>> 2 ^ D) & 858993459, D ^= B, R ^= B << 2, B = (D >>> -16 ^ R) & 65535, R ^= B, D ^= B << -16, B = (R >>> 1 ^ D) & 1431655765, D ^= B, R ^= B << 1, B = (D >>> 8 ^ R) & 16711935, R ^= B, D ^= B << 8, B = (R >>> 1 ^ D) & 1431655765, D ^= B, R ^= B << 1, B = R << 8 | D >>> 20 & 240, R = D << 24 | D << 8 & 16711680 | D >>> 8 & 65280 | D >>> 24 & 240, D = B;
            for (var G = 0; G < I.length; ++G) {
               I[G] ? (R = R << 2 | R >>> 26, D = D << 2 | D >>> 26) : (R = R << 1 | R >>> 27, D = D << 1 | D >>> 27), R &= -15, D &= -15;
               var z = t[R >>> 28] | a[R >>> 24 & 15] | r[R >>> 20 & 15] | n[R >>> 16 & 15] | i[R >>> 12 & 15] | s[R >>> 8 & 15] | o[R >>> 4 & 15],
                  oe = u[D >>> 28] | l[D >>> 24 & 15] | c[D >>> 20 & 15] | f[D >>> 16 & 15] | y[D >>> 12 & 15] | g[D >>> 8 & 15] | m[D >>> 4 & 15];
               B = (oe >>> 16 ^ z) & 65535, T[A++] = z ^ B, T[A++] = oe ^ B << 16
            }
         }
         return T
      }

      function Vu(e, t, a, r) {
         var n = e.length === 32 ? 3 : 9,
            i;
         n === 3 ? i = r ? [30, -2, -2] : [0, 32, 2] : i = r ? [94, 62, -2, 32, 64, 2, 30, -2, -2] : [0, 32, 2, 62, 30, -2, 64, 96, 2];
         var s, o = t[0],
            u = t[1];
         s = (o >>> 4 ^ u) & 252645135, u ^= s, o ^= s << 4, s = (o >>> 16 ^ u) & 65535, u ^= s, o ^= s << 16, s = (u >>> 2 ^ o) & 858993459, o ^= s, u ^= s << 2, s = (u >>> 8 ^ o) & 16711935, o ^= s, u ^= s << 8, s = (o >>> 1 ^ u) & 1431655765, u ^= s, o ^= s << 1, o = o << 1 | o >>> 31, u = u << 1 | u >>> 31;
         for (var l = 0; l < n; l += 3) {
            for (var c = i[l + 1], f = i[l + 2], y = i[l]; y != c; y += f) {
               var g = u ^ e[y],
                  m = (u >>> 4 | u << 28) ^ e[y + 1];
               s = o, o = u, u = s ^ (w0[g >>> 24 & 63] | _0[g >>> 16 & 63] | R0[g >>> 8 & 63] | k0[g & 63] | B0[m >>> 24 & 63] | N0[m >>> 16 & 63] | D0[m >>> 8 & 63] | L0[m & 63])
            }
            s = o, o = u, u = s
         }
         o = o >>> 1 | o << 31, u = u >>> 1 | u << 31, s = (o >>> 1 ^ u) & 1431655765, u ^= s, o ^= s << 1, s = (u >>> 8 ^ o) & 16711935, o ^= s, u ^= s << 8, s = (u >>> 2 ^ o) & 858993459, o ^= s, u ^= s << 2, s = (o >>> 16 ^ u) & 65535, u ^= s, o ^= s << 16, s = (o >>> 4 ^ u) & 252645135, u ^= s, o ^= s << 4, a[0] = o, a[1] = u
      }

      function Gn(e) {
         e = e || {};
         var t = (e.mode || "CBC").toUpperCase(),
            a = "DES-" + t,
            r;
         e.decrypt ? r = Ce.cipher.createDecipher(a, e.key) : r = Ce.cipher.createCipher(a, e.key);
         var n = r.start;
         return r.start = function(i, s) {
            var o = null;
            s instanceof Ce.util.ByteBuffer && (o = s, s = {}), s = s || {}, s.output = o, s.iv = i, n.call(r, s)
         }, r
      }
   });
   var zn = Y((Cg, Ku) => {
      "use strict";
      var rt = $();
      Jr();
      Rt();
      ae();
      var U0 = rt.pkcs5 = rt.pkcs5 || {},
         Zt;
      rt.util.isNodejs && !rt.options.usePureJavaScript && (Zt = gn("crypto"));
      Ku.exports = rt.pbkdf2 = U0.pbkdf2 = function(e, t, a, r, n, i) {
         if (typeof n == "function" && (i = n, n = null), rt.util.isNodejs && !rt.options.usePureJavaScript && Zt.pbkdf2 && (n === null || typeof n != "object") && (Zt.pbkdf2Sync.length > 4 || !n || n === "sha1")) return typeof n != "string" && (n = "sha1"), e = Buffer.from(e, "binary"), t = Buffer.from(t, "binary"), i ? Zt.pbkdf2Sync.length === 4 ? Zt.pbkdf2(e, t, a, r, function(B, F) {
            if (B) return i(B);
            i(null, F.toString("binary"))
         }) : Zt.pbkdf2(e, t, a, r, n, function(B, F) {
            if (B) return i(B);
            i(null, F.toString("binary"))
         }) : Zt.pbkdf2Sync.length === 4 ? Zt.pbkdf2Sync(e, t, a, r).toString("binary") : Zt.pbkdf2Sync(e, t, a, r, n).toString("binary");
         if ((typeof n > "u" || n === null) && (n = "sha1"), typeof n == "string") {
            if (!(n in rt.md.algorithms)) throw new Error("Unknown hash algorithm: " + n);
            n = rt.md[n].create()
         }
         var s = n.digestLength;
         if (r > 4294967295 * s) {
            var o = new Error("Derived key is too long.");
            if (i) return i(o);
            throw o
         }
         var u = Math.ceil(r / s),
            l = r - (u - 1) * s,
            c = rt.hmac.create();
         c.start(n, e);
         var f = "",
            y, g, m;
         if (!i) {
            for (var x = 1; x <= u; ++x) {
               c.start(null, null), c.update(t), c.update(rt.util.int32ToBytes(x)), y = m = c.digest().getBytes();
               for (var T = 2; T <= a; ++T) c.start(null, null), c.update(m), g = c.digest().getBytes(), y = rt.util.xorBytes(y, g, s), m = g;
               f += x < u ? y : y.substr(0, l)
            }
            return f
         }
         var x = 1,
            T;

         function I() {
            if (x > u) return i(null, f);
            c.start(null, null), c.update(t), c.update(rt.util.int32ToBytes(x)), y = m = c.digest().getBytes(), T = 2, A()
         }

         function A() {
            if (T <= a) return c.start(null, null), c.update(m), g = c.digest().getBytes(), y = rt.util.xorBytes(y, g, s), m = g, ++T, rt.util.setImmediate(A);
            f += x < u ? y : y.substr(0, l), ++x, I()
         }
         I()
      }
   });
   var ls = Y((xg, Wu) => {
      "use strict";
      var Ot = $();
      Rt();
      ae();
      var Hu = Wu.exports = Ot.sha256 = Ot.sha256 || {};
      Ot.md.sha256 = Ot.md.algorithms.sha256 = Hu;
      Hu.create = function() {
         Gu || F0();
         var e = null,
            t = Ot.util.createBuffer(),
            a = new Array(64),
            r = {
               algorithm: "sha256",
               blockLength: 64,
               digestLength: 32,
               messageLength: 0,
               fullMessageLength: null,
               messageLengthSize: 8
            };
         return r.start = function() {
            r.messageLength = 0, r.fullMessageLength = r.messageLength64 = [];
            for (var n = r.messageLengthSize / 4, i = 0; i < n; ++i) r.fullMessageLength.push(0);
            return t = Ot.util.createBuffer(), e = {
               h0: 1779033703,
               h1: 3144134277,
               h2: 1013904242,
               h3: 2773480762,
               h4: 1359893119,
               h5: 2600822924,
               h6: 528734635,
               h7: 1541459225
            }, r
         }, r.start(), r.update = function(n, i) {
            i === "utf8" && (n = Ot.util.encodeUtf8(n));
            var s = n.length;
            r.messageLength += s, s = [s / 4294967296 >>> 0, s >>> 0];
            for (var o = r.fullMessageLength.length - 1; o >= 0; --o) r.fullMessageLength[o] += s[1], s[1] = s[0] + (r.fullMessageLength[o] / 4294967296 >>> 0), r.fullMessageLength[o] = r.fullMessageLength[o] >>> 0, s[0] = s[1] / 4294967296 >>> 0;
            return t.putBytes(n), qu(e, a, t), (t.read > 2048 || t.length() === 0) && t.compact(), r
         }, r.digest = function() {
            var n = Ot.util.createBuffer();
            n.putBytes(t.bytes());
            var i = r.fullMessageLength[r.fullMessageLength.length - 1] + r.messageLengthSize,
               s = i & r.blockLength - 1;
            n.putBytes(us.substr(0, r.blockLength - s));
            for (var o, u, l = r.fullMessageLength[0] * 8, c = 0; c < r.fullMessageLength.length - 1; ++c) o = r.fullMessageLength[c + 1] * 8, u = o / 4294967296 >>> 0, l += u, n.putInt32(l >>> 0), l = o >>> 0;
            n.putInt32(l);
            var f = {
               h0: e.h0,
               h1: e.h1,
               h2: e.h2,
               h3: e.h3,
               h4: e.h4,
               h5: e.h5,
               h6: e.h6,
               h7: e.h7
            };
            qu(f, a, n);
            var y = Ot.util.createBuffer();
            return y.putInt32(f.h0), y.putInt32(f.h1), y.putInt32(f.h2), y.putInt32(f.h3), y.putInt32(f.h4), y.putInt32(f.h5), y.putInt32(f.h6), y.putInt32(f.h7), y
         }, r
      };
      var us = null,
         Gu = !1,
         zu = null;

      function F0() {
         us = String.fromCharCode(128), us += Ot.util.fillString(String.fromCharCode(0), 64), zu = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298], Gu = !0
      }

      function qu(e, t, a) {
         for (var r, n, i, s, o, u, l, c, f, y, g, m, x, T, I, A = a.length(); A >= 64;) {
            for (l = 0; l < 16; ++l) t[l] = a.getInt32();
            for (; l < 64; ++l) r = t[l - 2], r = (r >>> 17 | r << 15) ^ (r >>> 19 | r << 13) ^ r >>> 10, n = t[l - 15], n = (n >>> 7 | n << 25) ^ (n >>> 18 | n << 14) ^ n >>> 3, t[l] = r + t[l - 7] + n + t[l - 16] | 0;
            for (c = e.h0, f = e.h1, y = e.h2, g = e.h3, m = e.h4, x = e.h5, T = e.h6, I = e.h7, l = 0; l < 64; ++l) s = (m >>> 6 | m << 26) ^ (m >>> 11 | m << 21) ^ (m >>> 25 | m << 7), o = T ^ m & (x ^ T), i = (c >>> 2 | c << 30) ^ (c >>> 13 | c << 19) ^ (c >>> 22 | c << 10), u = c & f | y & (c ^ f), r = I + s + o + zu[l] + t[l], n = i + u, I = T, T = x, x = m, m = g + r >>> 0, g = y, y = f, f = c, c = r + n >>> 0;
            e.h0 = e.h0 + c | 0, e.h1 = e.h1 + f | 0, e.h2 = e.h2 + y | 0, e.h3 = e.h3 + g | 0, e.h4 = e.h4 + m | 0, e.h5 = e.h5 + x | 0, e.h6 = e.h6 + T | 0, e.h7 = e.h7 + I | 0, A -= 64
         }
      }
   });
   var cs = Y((Tg, Yu) => {
      "use strict";
      var Ut = $();
      ae();
      var Wn = null;
      Ut.util.isNodejs && !Ut.options.usePureJavaScript && !process.versions["node-webkit"] && (Wn = gn("crypto"));
      var P0 = Yu.exports = Ut.prng = Ut.prng || {};
      P0.create = function(e) {
         for (var t = {
               plugin: e,
               key: null,
               seed: null,
               time: null,
               reseeds: 0,
               generated: 0,
               keyBytes: ""
            }, a = e.md, r = new Array(32), n = 0; n < 32; ++n) r[n] = a.create();
         t.pools = r, t.pool = 0, t.generate = function(l, c) {
            if (!c) return t.generateSync(l);
            var f = t.plugin.cipher,
               y = t.plugin.increment,
               g = t.plugin.formatKey,
               m = t.plugin.formatSeed,
               x = Ut.util.createBuffer();
            t.key = null, T();

            function T(I) {
               if (I) return c(I);
               if (x.length() >= l) return c(null, x.getBytes(l));
               if (t.generated > 1048575 && (t.key = null), t.key === null) return Ut.util.nextTick(function() {
                  i(T)
               });
               var A = f(t.key, t.seed);
               t.generated += A.length, x.putBytes(A), t.key = g(f(t.key, y(t.seed))), t.seed = m(f(t.key, t.seed)), Ut.util.setImmediate(T)
            }
         }, t.generateSync = function(l) {
            var c = t.plugin.cipher,
               f = t.plugin.increment,
               y = t.plugin.formatKey,
               g = t.plugin.formatSeed;
            t.key = null;
            for (var m = Ut.util.createBuffer(); m.length() < l;) {
               t.generated > 1048575 && (t.key = null), t.key === null && s();
               var x = c(t.key, t.seed);
               t.generated += x.length, m.putBytes(x), t.key = y(c(t.key, f(t.seed))), t.seed = g(c(t.key, t.seed))
            }
            return m.getBytes(l)
         };

         function i(l) {
            if (t.pools[0].messageLength >= 32) return o(), l();
            var c = 32 - t.pools[0].messageLength << 5;
            t.seedFile(c, function(f, y) {
               if (f) return l(f);
               t.collect(y), o(), l()
            })
         }

         function s() {
            if (t.pools[0].messageLength >= 32) return o();
            var l = 32 - t.pools[0].messageLength << 5;
            t.collect(t.seedFileSync(l)), o()
         }

         function o() {
            t.reseeds = t.reseeds === 4294967295 ? 0 : t.reseeds + 1;
            var l = t.plugin.md.create();
            l.update(t.keyBytes);
            for (var c = 1, f = 0; f < 32; ++f) t.reseeds % c === 0 && (l.update(t.pools[f].digest().getBytes()), t.pools[f].start()), c = c << 1;
            t.keyBytes = l.digest().getBytes(), l.start(), l.update(t.keyBytes);
            var y = l.digest().getBytes();
            t.key = t.plugin.formatKey(t.keyBytes), t.seed = t.plugin.formatSeed(y), t.generated = 0
         }

         function u(l) {
            var c = null,
               f = Ut.util.globalScope,
               y = f.crypto || f.msCrypto;
            y && y.getRandomValues && (c = function(R) {
               return y.getRandomValues(R)
            });
            var g = Ut.util.createBuffer();
            if (c)
               for (; g.length() < l;) {
                  var m = Math.max(1, Math.min(l - g.length(), 65536) / 4),
                     x = new Uint32Array(Math.floor(m));
                  try {
                     c(x);
                     for (var T = 0; T < x.length; ++T) g.putInt32(x[T])
                  } catch (R) {
                     if (!(typeof QuotaExceededError < "u" && R instanceof QuotaExceededError)) throw R
                  }
               }
            if (g.length() < l)
               for (var I, A, B, F = Math.floor(Math.random() * 65536); g.length() < l;) {
                  A = 16807 * (F & 65535), I = 16807 * (F >> 16), A += (I & 32767) << 16, A += I >> 15, A = (A & 2147483647) + (A >> 31), F = A & 4294967295;
                  for (var T = 0; T < 3; ++T) B = F >>> (T << 3), B ^= Math.floor(Math.random() * 256), g.putByte(B & 255)
               }
            return g.getBytes(l)
         }
         return Wn ? (t.seedFile = function(l, c) {
            Wn.randomBytes(l, function(f, y) {
               if (f) return c(f);
               c(null, y.toString())
            })
         }, t.seedFileSync = function(l) {
            return Wn.randomBytes(l).toString()
         }) : (t.seedFile = function(l, c) {
            try {
               c(null, u(l))
            } catch (f) {
               c(f)
            }
         }, t.seedFileSync = u), t.collect = function(l) {
            for (var c = l.length, f = 0; f < c; ++f) t.pools[t.pool].update(l.substr(f, 1)), t.pool = t.pool === 31 ? 0 : t.pool + 1
         }, t.collectInt = function(l, c) {
            for (var f = "", y = 0; y < c; y += 8) f += String.fromCharCode(l >> y & 255);
            t.collect(f)
         }, t.registerWorker = function(l) {
            if (l === self) t.seedFile = function(f, y) {
               function g(m) {
                  var x = m.data;
                  x.forge && x.forge.prng && (self.removeEventListener("message", g), y(x.forge.prng.err, x.forge.prng.bytes))
               }
               self.addEventListener("message", g), self.postMessage({
                  forge: {
                     prng: {
                        needed: f
                     }
                  }
               })
            };
            else {
               var c = function(f) {
                  var y = f.data;
                  y.forge && y.forge.prng && t.seedFile(y.forge.prng.needed, function(g, m) {
                     l.postMessage({
                        forge: {
                           prng: {
                              err: g,
                              bytes: m
                           }
                        }
                     })
                  })
               };
               l.addEventListener("message", c)
            }
         }, t
      }
   });
   var mt = Y((Sg, fs) => {
      "use strict";
      var Oe = $();
      sr();
      ls();
      cs();
      ae();
      (function() {
         if (Oe.random && Oe.random.getBytes) {
            fs.exports = Oe.random;
            return
         }(function(e) {
            var t = {},
               a = new Array(4),
               r = Oe.util.createBuffer();
            t.formatKey = function(f) {
               var y = Oe.util.createBuffer(f);
               return f = new Array(4), f[0] = y.getInt32(), f[1] = y.getInt32(), f[2] = y.getInt32(), f[3] = y.getInt32(), Oe.aes._expandKey(f, !1)
            }, t.formatSeed = function(f) {
               var y = Oe.util.createBuffer(f);
               return f = new Array(4), f[0] = y.getInt32(), f[1] = y.getInt32(), f[2] = y.getInt32(), f[3] = y.getInt32(), f
            }, t.cipher = function(f, y) {
               return Oe.aes._updateBlock(f, y, a, !1), r.putInt32(a[0]), r.putInt32(a[1]), r.putInt32(a[2]), r.putInt32(a[3]), r.getBytes()
            }, t.increment = function(f) {
               return ++f[3], f
            }, t.md = Oe.md.sha256;

            function n() {
               var f = Oe.prng.create(t);
               return f.getBytes = function(y, g) {
                  return f.generate(y, g)
               }, f.getBytesSync = function(y) {
                  return f.generate(y)
               }, f
            }
            var i = n(),
               s = null,
               o = Oe.util.globalScope,
               u = o.crypto || o.msCrypto;
            if (u && u.getRandomValues && (s = function(f) {
                  return u.getRandomValues(f)
               }), Oe.options.usePureJavaScript || !Oe.util.isNodejs && !s) {
               if (typeof window > "u" || window.document, i.collectInt(+new Date, 32), typeof navigator < "u") {
                  var l = "";
                  for (var c in navigator) try {
                     typeof navigator[c] == "string" && (l += navigator[c])
                  } catch {}
                  i.collect(l), l = null
               }
               e && (e().mousemove(function(f) {
                  i.collectInt(f.clientX, 16), i.collectInt(f.clientY, 16)
               }), e().keypress(function(f) {
                  i.collectInt(f.charCode, 8)
               }))
            }
            if (!Oe.random) Oe.random = i;
            else
               for (var c in i) Oe.random[c] = i[c];
            Oe.random.createInstance = n, fs.exports = Oe.random
         })(typeof jQuery < "u" ? jQuery : null)
      })()
   });
   var ds = Y((Ig, $u) => {
      "use strict";
      var st = $();
      ae();
      var hs = [217, 120, 249, 196, 25, 221, 181, 237, 40, 233, 253, 121, 74, 160, 216, 157, 198, 126, 55, 131, 43, 118, 83, 142, 98, 76, 100, 136, 68, 139, 251, 162, 23, 154, 89, 245, 135, 179, 79, 19, 97, 69, 109, 141, 9, 129, 125, 50, 189, 143, 64, 235, 134, 183, 123, 11, 240, 149, 33, 34, 92, 107, 78, 130, 84, 214, 101, 147, 206, 96, 178, 28, 115, 86, 192, 20, 167, 140, 241, 220, 18, 117, 202, 31, 59, 190, 228, 209, 66, 61, 212, 48, 163, 60, 182, 38, 111, 191, 14, 218, 70, 105, 7, 87, 39, 242, 29, 155, 188, 148, 67, 3, 248, 17, 199, 246, 144, 239, 62, 231, 6, 195, 213, 47, 200, 102, 30, 215, 8, 232, 234, 222, 128, 82, 238, 247, 132, 170, 114, 172, 53, 77, 106, 42, 150, 26, 210, 113, 90, 21, 73, 116, 75, 159, 208, 94, 4, 24, 164, 236, 194, 224, 65, 110, 15, 81, 203, 204, 36, 145, 175, 80, 161, 244, 112, 57, 153, 124, 58, 133, 35, 184, 180, 122, 252, 2, 54, 91, 37, 85, 151, 49, 45, 93, 250, 152, 227, 138, 146, 174, 5, 223, 41, 16, 103, 108, 186, 201, 211, 0, 230, 207, 225, 158, 168, 44, 99, 22, 1, 63, 88, 226, 137, 169, 13, 56, 52, 27, 171, 51, 255, 176, 187, 72, 12, 95, 185, 177, 205, 46, 197, 243, 219, 71, 229, 165, 156, 119, 10, 166, 32, 104, 254, 127, 193, 173],
         Zu = [1, 2, 3, 5],
         V0 = function(e, t) {
            return e << t & 65535 | (e & 65535) >> 16 - t
         },
         M0 = function(e, t) {
            return (e & 65535) >> t | e << 16 - t & 65535
         };
      $u.exports = st.rc2 = st.rc2 || {};
      st.rc2.expandKey = function(e, t) {
         typeof e == "string" && (e = st.util.createBuffer(e)), t = t || 128;
         var a = e,
            r = e.length(),
            n = t,
            i = Math.ceil(n / 8),
            s = 255 >> (n & 7),
            o;
         for (o = r; o < 128; o++) a.putByte(hs[a.at(o - 1) + a.at(o - r) & 255]);
         for (a.setAt(128 - i, hs[a.at(128 - i) & s]), o = 127 - i; o >= 0; o--) a.setAt(o, hs[a.at(o + 1) ^ a.at(o + i)]);
         return a
      };
      var Qu = function(e, t, a) {
         var r = !1,
            n = null,
            i = null,
            s = null,
            o, u, l, c, f = [];
         for (e = st.rc2.expandKey(e, t), l = 0; l < 64; l++) f.push(e.getInt16Le());
         a ? (o = function(m) {
            for (l = 0; l < 4; l++) m[l] += f[c] + (m[(l + 3) % 4] & m[(l + 2) % 4]) + (~m[(l + 3) % 4] & m[(l + 1) % 4]), m[l] = V0(m[l], Zu[l]), c++
         }, u = function(m) {
            for (l = 0; l < 4; l++) m[l] += f[m[(l + 3) % 4] & 63]
         }) : (o = function(m) {
            for (l = 3; l >= 0; l--) m[l] = M0(m[l], Zu[l]), m[l] -= f[c] + (m[(l + 3) % 4] & m[(l + 2) % 4]) + (~m[(l + 3) % 4] & m[(l + 1) % 4]), c--
         }, u = function(m) {
            for (l = 3; l >= 0; l--) m[l] -= f[m[(l + 3) % 4] & 63]
         });
         var y = function(m) {
               var x = [];
               for (l = 0; l < 4; l++) {
                  var T = n.getInt16Le();
                  s !== null && (a ? T ^= s.getInt16Le() : s.putInt16Le(T)), x.push(T & 65535)
               }
               c = a ? 0 : 63;
               for (var I = 0; I < m.length; I++)
                  for (var A = 0; A < m[I][0]; A++) m[I][1](x);
               for (l = 0; l < 4; l++) s !== null && (a ? s.putInt16Le(x[l]) : x[l] ^= s.getInt16Le()), i.putInt16Le(x[l])
            },
            g = null;
         return g = {
            start: function(m, x) {
               m && typeof m == "string" && (m = st.util.createBuffer(m)), r = !1, n = st.util.createBuffer(), i = x || new st.util.createBuffer, s = m, g.output = i
            },
            update: function(m) {
               for (r || n.putBuffer(m); n.length() >= 8;) y([
                  [5, o],
                  [1, u],
                  [6, o],
                  [1, u],
                  [5, o]
               ])
            },
            finish: function(m) {
               var x = !0;
               if (a)
                  if (m) x = m(8, n, !a);
                  else {
                     var T = n.length() === 8 ? 8 : 8 - n.length();
                     n.fillWithByte(T, T)
                  } if (x && (r = !0, g.update()), !a && (x = n.length() === 0, x))
                  if (m) x = m(8, i, !a);
                  else {
                     var I = i.length(),
                        A = i.at(I - 1);
                     A > I ? x = !1 : i.truncate(A)
                  } return x
            }
         }, g
      };
      st.rc2.startEncrypting = function(e, t, a) {
         var r = st.rc2.createEncryptionCipher(e, 128);
         return r.start(t, a), r
      };
      st.rc2.createEncryptionCipher = function(e, t) {
         return Qu(e, t, !0)
      };
      st.rc2.startDecrypting = function(e, t, a) {
         var r = st.rc2.createDecryptionCipher(e, 128);
         return r.start(t, a), r
      };
      st.rc2.createDecryptionCipher = function(e, t) {
         return Qu(e, t, !1)
      }
   });
   var tn = Y((bg, nl) => {
      "use strict";
      var ps = $();
      nl.exports = ps.jsbn = ps.jsbn || {};
      var Qt, K0 = 0xdeadbeefcafe,
         ju = (K0 & 16777215) == 15715070;

      function w(e, t, a) {
         this.data = [], e != null && (typeof e == "number" ? this.fromNumber(e, t, a) : t == null && typeof e != "string" ? this.fromString(e, 256) : this.fromString(e, t))
      }
      ps.jsbn.BigInteger = w;

      function ne() {
         return new w(null)
      }

      function q0(e, t, a, r, n, i) {
         for (; --i >= 0;) {
            var s = t * this.data[e++] + a.data[r] + n;
            n = Math.floor(s / 67108864), a.data[r++] = s & 67108863
         }
         return n
      }

      function H0(e, t, a, r, n, i) {
         for (var s = t & 32767, o = t >> 15; --i >= 0;) {
            var u = this.data[e] & 32767,
               l = this.data[e++] >> 15,
               c = o * u + l * s;
            u = s * u + ((c & 32767) << 15) + a.data[r] + (n & 1073741823), n = (u >>> 30) + (c >>> 15) + o * l + (n >>> 30), a.data[r++] = u & 1073741823
         }
         return n
      }

      function Xu(e, t, a, r, n, i) {
         for (var s = t & 16383, o = t >> 14; --i >= 0;) {
            var u = this.data[e] & 16383,
               l = this.data[e++] >> 14,
               c = o * u + l * s;
            u = s * u + ((c & 16383) << 14) + a.data[r] + n, n = (u >> 28) + (c >> 14) + o * l, a.data[r++] = u & 268435455
         }
         return n
      }
      typeof navigator > "u" ? (w.prototype.am = Xu, Qt = 28) : ju && navigator.appName == "Microsoft Internet Explorer" ? (w.prototype.am = H0, Qt = 30) : ju && navigator.appName != "Netscape" ? (w.prototype.am = q0, Qt = 26) : (w.prototype.am = Xu, Qt = 28);
      w.prototype.DB = Qt;
      w.prototype.DM = (1 << Qt) - 1;
      w.prototype.DV = 1 << Qt;
      var ys = 52;
      w.prototype.FV = Math.pow(2, ys);
      w.prototype.F1 = ys - Qt;
      w.prototype.F2 = 2 * Qt - ys;
      var G0 = "0123456789abcdefghijklmnopqrstuvwxyz",
         Yn = new Array,
         ta, gt;
      ta = "0".charCodeAt(0);
      for (gt = 0; gt <= 9; ++gt) Yn[ta++] = gt;
      ta = "a".charCodeAt(0);
      for (gt = 10; gt < 36; ++gt) Yn[ta++] = gt;
      ta = "A".charCodeAt(0);
      for (gt = 10; gt < 36; ++gt) Yn[ta++] = gt;

      function Ju(e) {
         return G0.charAt(e)
      }

      function el(e, t) {
         var a = Yn[e.charCodeAt(t)];
         return a ?? -1
      }

      function z0(e) {
         for (var t = this.t - 1; t >= 0; --t) e.data[t] = this.data[t];
         e.t = this.t, e.s = this.s
      }

      function W0(e) {
         this.t = 1, this.s = e < 0 ? -1 : 0, e > 0 ? this.data[0] = e : e < -1 ? this.data[0] = e + this.DV : this.t = 0
      }

      function ur(e) {
         var t = ne();
         return t.fromInt(e), t
      }

      function Y0(e, t) {
         var a;
         if (t == 16) a = 4;
         else if (t == 8) a = 3;
         else if (t == 256) a = 8;
         else if (t == 2) a = 1;
         else if (t == 32) a = 5;
         else if (t == 4) a = 2;
         else {
            this.fromRadix(e, t);
            return
         }
         this.t = 0, this.s = 0;
         for (var r = e.length, n = !1, i = 0; --r >= 0;) {
            var s = a == 8 ? e[r] & 255 : el(e, r);
            if (s < 0) {
               e.charAt(r) == "-" && (n = !0);
               continue
            }
            n = !1, i == 0 ? this.data[this.t++] = s : i + a > this.DB ? (this.data[this.t - 1] |= (s & (1 << this.DB - i) - 1) << i, this.data[this.t++] = s >> this.DB - i) : this.data[this.t - 1] |= s << i, i += a, i >= this.DB && (i -= this.DB)
         }
         a == 8 && e[0] & 128 && (this.s = -1, i > 0 && (this.data[this.t - 1] |= (1 << this.DB - i) - 1 << i)), this.clamp(), n && w.ZERO.subTo(this, this)
      }

      function Z0() {
         for (var e = this.s & this.DM; this.t > 0 && this.data[this.t - 1] == e;) --this.t
      }

      function Q0(e) {
         if (this.s < 0) return "-" + this.negate().toString(e);
         var t;
         if (e == 16) t = 4;
         else if (e == 8) t = 3;
         else if (e == 2) t = 1;
         else if (e == 32) t = 5;
         else if (e == 4) t = 2;
         else return this.toRadix(e);
         var a = (1 << t) - 1,
            r, n = !1,
            i = "",
            s = this.t,
            o = this.DB - s * this.DB % t;
         if (s-- > 0)
            for (o < this.DB && (r = this.data[s] >> o) > 0 && (n = !0, i = Ju(r)); s >= 0;) o < t ? (r = (this.data[s] & (1 << o) - 1) << t - o, r |= this.data[--s] >> (o += this.DB - t)) : (r = this.data[s] >> (o -= t) & a, o <= 0 && (o += this.DB, --s)), r > 0 && (n = !0), n && (i += Ju(r));
         return n ? i : "0"
      }

      function $0() {
         var e = ne();
         return w.ZERO.subTo(this, e), e
      }

      function j0() {
         return this.s < 0 ? this.negate() : this
      }

      function X0(e) {
         var t = this.s - e.s;
         if (t != 0) return t;
         var a = this.t;
         if (t = a - e.t, t != 0) return this.s < 0 ? -t : t;
         for (; --a >= 0;)
            if ((t = this.data[a] - e.data[a]) != 0) return t;
         return 0
      }

      function Zn(e) {
         var t = 1,
            a;
         return (a = e >>> 16) != 0 && (e = a, t += 16), (a = e >> 8) != 0 && (e = a, t += 8), (a = e >> 4) != 0 && (e = a, t += 4), (a = e >> 2) != 0 && (e = a, t += 2), (a = e >> 1) != 0 && (e = a, t += 1), t
      }

      function J0() {
         return this.t <= 0 ? 0 : this.DB * (this.t - 1) + Zn(this.data[this.t - 1] ^ this.s & this.DM)
      }

      function eh(e, t) {
         var a;
         for (a = this.t - 1; a >= 0; --a) t.data[a + e] = this.data[a];
         for (a = e - 1; a >= 0; --a) t.data[a] = 0;
         t.t = this.t + e, t.s = this.s
      }

      function th(e, t) {
         for (var a = e; a < this.t; ++a) t.data[a - e] = this.data[a];
         t.t = Math.max(this.t - e, 0), t.s = this.s
      }

      function rh(e, t) {
         var a = e % this.DB,
            r = this.DB - a,
            n = (1 << r) - 1,
            i = Math.floor(e / this.DB),
            s = this.s << a & this.DM,
            o;
         for (o = this.t - 1; o >= 0; --o) t.data[o + i + 1] = this.data[o] >> r | s, s = (this.data[o] & n) << a;
         for (o = i - 1; o >= 0; --o) t.data[o] = 0;
         t.data[i] = s, t.t = this.t + i + 1, t.s = this.s, t.clamp()
      }

      function ah(e, t) {
         t.s = this.s;
         var a = Math.floor(e / this.DB);
         if (a >= this.t) {
            t.t = 0;
            return
         }
         var r = e % this.DB,
            n = this.DB - r,
            i = (1 << r) - 1;
         t.data[0] = this.data[a] >> r;
         for (var s = a + 1; s < this.t; ++s) t.data[s - a - 1] |= (this.data[s] & i) << n, t.data[s - a] = this.data[s] >> r;
         r > 0 && (t.data[this.t - a - 1] |= (this.s & i) << n), t.t = this.t - a, t.clamp()
      }

      function nh(e, t) {
         for (var a = 0, r = 0, n = Math.min(e.t, this.t); a < n;) r += this.data[a] - e.data[a], t.data[a++] = r & this.DM, r >>= this.DB;
         if (e.t < this.t) {
            for (r -= e.s; a < this.t;) r += this.data[a], t.data[a++] = r & this.DM, r >>= this.DB;
            r += this.s
         } else {
            for (r += this.s; a < e.t;) r -= e.data[a], t.data[a++] = r & this.DM, r >>= this.DB;
            r -= e.s
         }
         t.s = r < 0 ? -1 : 0, r < -1 ? t.data[a++] = this.DV + r : r > 0 && (t.data[a++] = r), t.t = a, t.clamp()
      }

      function ih(e, t) {
         var a = this.abs(),
            r = e.abs(),
            n = a.t;
         for (t.t = n + r.t; --n >= 0;) t.data[n] = 0;
         for (n = 0; n < r.t; ++n) t.data[n + a.t] = a.am(0, r.data[n], t, n, 0, a.t);
         t.s = 0, t.clamp(), this.s != e.s && w.ZERO.subTo(t, t)
      }

      function sh(e) {
         for (var t = this.abs(), a = e.t = 2 * t.t; --a >= 0;) e.data[a] = 0;
         for (a = 0; a < t.t - 1; ++a) {
            var r = t.am(a, t.data[a], e, 2 * a, 0, 1);
            (e.data[a + t.t] += t.am(a + 1, 2 * t.data[a], e, 2 * a + 1, r, t.t - a - 1)) >= t.DV && (e.data[a + t.t] -= t.DV, e.data[a + t.t + 1] = 1)
         }
         e.t > 0 && (e.data[e.t - 1] += t.am(a, t.data[a], e, 2 * a, 0, 1)), e.s = 0, e.clamp()
      }

      function oh(e, t, a) {
         var r = e.abs();
         if (!(r.t <= 0)) {
            var n = this.abs();
            if (n.t < r.t) {
               t?.fromInt(0), a != null && this.copyTo(a);
               return
            }
            a == null && (a = ne());
            var i = ne(),
               s = this.s,
               o = e.s,
               u = this.DB - Zn(r.data[r.t - 1]);
            u > 0 ? (r.lShiftTo(u, i), n.lShiftTo(u, a)) : (r.copyTo(i), n.copyTo(a));
            var l = i.t,
               c = i.data[l - 1];
            if (c != 0) {
               var f = c * (1 << this.F1) + (l > 1 ? i.data[l - 2] >> this.F2 : 0),
                  y = this.FV / f,
                  g = (1 << this.F1) / f,
                  m = 1 << this.F2,
                  x = a.t,
                  T = x - l,
                  I = t ?? ne();
               for (i.dlShiftTo(T, I), a.compareTo(I) >= 0 && (a.data[a.t++] = 1, a.subTo(I, a)), w.ONE.dlShiftTo(l, I), I.subTo(i, i); i.t < l;) i.data[i.t++] = 0;
               for (; --T >= 0;) {
                  var A = a.data[--x] == c ? this.DM : Math.floor(a.data[x] * y + (a.data[x - 1] + m) * g);
                  if ((a.data[x] += i.am(0, A, a, T, 0, l)) < A)
                     for (i.dlShiftTo(T, I), a.subTo(I, a); a.data[x] < --A;) a.subTo(I, a)
               }
               t != null && (a.drShiftTo(l, t), s != o && w.ZERO.subTo(t, t)), a.t = l, a.clamp(), u > 0 && a.rShiftTo(u, a), s < 0 && w.ZERO.subTo(a, a)
            }
         }
      }

      function uh(e) {
         var t = ne();
         return this.abs().divRemTo(e, null, t), this.s < 0 && t.compareTo(w.ZERO) > 0 && e.subTo(t, t), t
      }

      function Ir(e) {
         this.m = e
      }

      function lh(e) {
         return e.s < 0 || e.compareTo(this.m) >= 0 ? e.mod(this.m) : e
      }

      function ch(e) {
         return e
      }

      function fh(e) {
         e.divRemTo(this.m, null, e)
      }

      function hh(e, t, a) {
         e.multiplyTo(t, a), this.reduce(a)
      }

      function dh(e, t) {
         e.squareTo(t), this.reduce(t)
      }
      Ir.prototype.convert = lh;
      Ir.prototype.revert = ch;
      Ir.prototype.reduce = fh;
      Ir.prototype.mulTo = hh;
      Ir.prototype.sqrTo = dh;

      function ph() {
         if (this.t < 1) return 0;
         var e = this.data[0];
         if (!(e & 1)) return 0;
         var t = e & 3;
         return t = t * (2 - (e & 15) * t) & 15, t = t * (2 - (e & 255) * t) & 255, t = t * (2 - ((e & 65535) * t & 65535)) & 65535, t = t * (2 - e * t % this.DV) % this.DV, t > 0 ? this.DV - t : -t
      }

      function br(e) {
         this.m = e, this.mp = e.invDigit(), this.mpl = this.mp & 32767, this.mph = this.mp >> 15, this.um = (1 << e.DB - 15) - 1, this.mt2 = 2 * e.t
      }

      function yh(e) {
         var t = ne();
         return e.abs().dlShiftTo(this.m.t, t), t.divRemTo(this.m, null, t), e.s < 0 && t.compareTo(w.ZERO) > 0 && this.m.subTo(t, t), t
      }

      function mh(e) {
         var t = ne();
         return e.copyTo(t), this.reduce(t), t
      }

      function gh(e) {
         for (; e.t <= this.mt2;) e.data[e.t++] = 0;
         for (var t = 0; t < this.m.t; ++t) {
            var a = e.data[t] & 32767,
               r = a * this.mpl + ((a * this.mph + (e.data[t] >> 15) * this.mpl & this.um) << 15) & e.DM;
            for (a = t + this.m.t, e.data[a] += this.m.am(0, r, e, t, 0, this.m.t); e.data[a] >= e.DV;) e.data[a] -= e.DV, e.data[++a]++
         }
         e.clamp(), e.drShiftTo(this.m.t, e), e.compareTo(this.m) >= 0 && e.subTo(this.m, e)
      }

      function vh(e, t) {
         e.squareTo(t), this.reduce(t)
      }

      function Eh(e, t, a) {
         e.multiplyTo(t, a), this.reduce(a)
      }
      br.prototype.convert = yh;
      br.prototype.revert = mh;
      br.prototype.reduce = gh;
      br.prototype.mulTo = Eh;
      br.prototype.sqrTo = vh;

      function Ch() {
         return (this.t > 0 ? this.data[0] & 1 : this.s) == 0
      }

      function xh(e, t) {
         if (e > 4294967295 || e < 1) return w.ONE;
         var a = ne(),
            r = ne(),
            n = t.convert(this),
            i = Zn(e) - 1;
         for (n.copyTo(a); --i >= 0;)
            if (t.sqrTo(a, r), (e & 1 << i) > 0) t.mulTo(r, n, a);
            else {
               var s = a;
               a = r, r = s
            } return t.revert(a)
      }

      function Th(e, t) {
         var a;
         return e < 256 || t.isEven() ? a = new Ir(t) : a = new br(t), this.exp(e, a)
      }
      w.prototype.copyTo = z0;
      w.prototype.fromInt = W0;
      w.prototype.fromString = Y0;
      w.prototype.clamp = Z0;
      w.prototype.dlShiftTo = eh;
      w.prototype.drShiftTo = th;
      w.prototype.lShiftTo = rh;
      w.prototype.rShiftTo = ah;
      w.prototype.subTo = nh;
      w.prototype.multiplyTo = ih;
      w.prototype.squareTo = sh;
      w.prototype.divRemTo = oh;
      w.prototype.invDigit = ph;
      w.prototype.isEven = Ch;
      w.prototype.exp = xh;
      w.prototype.toString = Q0;
      w.prototype.negate = $0;
      w.prototype.abs = j0;
      w.prototype.compareTo = X0;
      w.prototype.bitLength = J0;
      w.prototype.mod = uh;
      w.prototype.modPowInt = Th;
      w.ZERO = ur(0);
      w.ONE = ur(1);

      function Sh() {
         var e = ne();
         return this.copyTo(e), e
      }

      function Ih() {
         if (this.s < 0) {
            if (this.t == 1) return this.data[0] - this.DV;
            if (this.t == 0) return -1
         } else {
            if (this.t == 1) return this.data[0];
            if (this.t == 0) return 0
         }
         return (this.data[1] & (1 << 32 - this.DB) - 1) << this.DB | this.data[0]
      }

      function bh() {
         return this.t == 0 ? this.s : this.data[0] << 24 >> 24
      }

      function Ah() {
         return this.t == 0 ? this.s : this.data[0] << 16 >> 16
      }

      function Bh(e) {
         return Math.floor(Math.LN2 * this.DB / Math.log(e))
      }

      function wh() {
         return this.s < 0 ? -1 : this.t <= 0 || this.t == 1 && this.data[0] <= 0 ? 0 : 1
      }

      function Nh(e) {
         if (e == null && (e = 10), this.signum() == 0 || e < 2 || e > 36) return "0";
         var t = this.chunkSize(e),
            a = Math.pow(e, t),
            r = ur(a),
            n = ne(),
            i = ne(),
            s = "";
         for (this.divRemTo(r, n, i); n.signum() > 0;) s = (a + i.intValue()).toString(e).substr(1) + s, n.divRemTo(r, n, i);
         return i.intValue().toString(e) + s
      }

      function _h(e, t) {
         this.fromInt(0), t == null && (t = 10);
         for (var a = this.chunkSize(t), r = Math.pow(t, a), n = !1, i = 0, s = 0, o = 0; o < e.length; ++o) {
            var u = el(e, o);
            if (u < 0) {
               e.charAt(o) == "-" && this.signum() == 0 && (n = !0);
               continue
            }
            s = t * s + u, ++i >= a && (this.dMultiply(r), this.dAddOffset(s, 0), i = 0, s = 0)
         }
         i > 0 && (this.dMultiply(Math.pow(t, i)), this.dAddOffset(s, 0)), n && w.ZERO.subTo(this, this)
      }

      function Dh(e, t, a) {
         if (typeof t == "number")
            if (e < 2) this.fromInt(1);
            else
               for (this.fromNumber(e, a), this.testBit(e - 1) || this.bitwiseTo(w.ONE.shiftLeft(e - 1), ms, this), this.isEven() && this.dAddOffset(1, 0); !this.isProbablePrime(t);) this.dAddOffset(2, 0), this.bitLength() > e && this.subTo(w.ONE.shiftLeft(e - 1), this);
         else {
            var r = new Array,
               n = e & 7;
            r.length = (e >> 3) + 1, t.nextBytes(r), n > 0 ? r[0] &= (1 << n) - 1 : r[0] = 0, this.fromString(r, 256)
         }
      }

      function Rh() {
         var e = this.t,
            t = new Array;
         t[0] = this.s;
         var a = this.DB - e * this.DB % 8,
            r, n = 0;
         if (e-- > 0)
            for (a < this.DB && (r = this.data[e] >> a) != (this.s & this.DM) >> a && (t[n++] = r | this.s << this.DB - a); e >= 0;) a < 8 ? (r = (this.data[e] & (1 << a) - 1) << 8 - a, r |= this.data[--e] >> (a += this.DB - 8)) : (r = this.data[e] >> (a -= 8) & 255, a <= 0 && (a += this.DB, --e)), r & 128 && (r |= -256), n == 0 && (this.s & 128) != (r & 128) && ++n, (n > 0 || r != this.s) && (t[n++] = r);
         return t
      }

      function Lh(e) {
         return this.compareTo(e) == 0
      }

      function kh(e) {
         return this.compareTo(e) < 0 ? this : e
      }

      function Oh(e) {
         return this.compareTo(e) > 0 ? this : e
      }

      function Uh(e, t, a) {
         var r, n, i = Math.min(e.t, this.t);
         for (r = 0; r < i; ++r) a.data[r] = t(this.data[r], e.data[r]);
         if (e.t < this.t) {
            for (n = e.s & this.DM, r = i; r < this.t; ++r) a.data[r] = t(this.data[r], n);
            a.t = this.t
         } else {
            for (n = this.s & this.DM, r = i; r < e.t; ++r) a.data[r] = t(n, e.data[r]);
            a.t = e.t
         }
         a.s = t(this.s, e.s), a.clamp()
      }

      function Fh(e, t) {
         return e & t
      }

      function Ph(e) {
         var t = ne();
         return this.bitwiseTo(e, Fh, t), t
      }

      function ms(e, t) {
         return e | t
      }

      function Vh(e) {
         var t = ne();
         return this.bitwiseTo(e, ms, t), t
      }

      function tl(e, t) {
         return e ^ t
      }

      function Mh(e) {
         var t = ne();
         return this.bitwiseTo(e, tl, t), t
      }

      function rl(e, t) {
         return e & ~t
      }

      function Kh(e) {
         var t = ne();
         return this.bitwiseTo(e, rl, t), t
      }

      function qh() {
         for (var e = ne(), t = 0; t < this.t; ++t) e.data[t] = this.DM & ~this.data[t];
         return e.t = this.t, e.s = ~this.s, e
      }

      function Hh(e) {
         var t = ne();
         return e < 0 ? this.rShiftTo(-e, t) : this.lShiftTo(e, t), t
      }

      function Gh(e) {
         var t = ne();
         return e < 0 ? this.lShiftTo(-e, t) : this.rShiftTo(e, t), t
      }

      function zh(e) {
         if (e == 0) return -1;
         var t = 0;
         return e & 65535 || (e >>= 16, t += 16), e & 255 || (e >>= 8, t += 8), e & 15 || (e >>= 4, t += 4), e & 3 || (e >>= 2, t += 2), e & 1 || ++t, t
      }

      function Wh() {
         for (var e = 0; e < this.t; ++e)
            if (this.data[e] != 0) return e * this.DB + zh(this.data[e]);
         return this.s < 0 ? this.t * this.DB : -1
      }

      function Yh(e) {
         for (var t = 0; e != 0;) e &= e - 1, ++t;
         return t
      }

      function Zh() {
         for (var e = 0, t = this.s & this.DM, a = 0; a < this.t; ++a) e += Yh(this.data[a] ^ t);
         return e
      }

      function Qh(e) {
         var t = Math.floor(e / this.DB);
         return t >= this.t ? this.s != 0 : (this.data[t] & 1 << e % this.DB) != 0
      }

      function $h(e, t) {
         var a = w.ONE.shiftLeft(e);
         return this.bitwiseTo(a, t, a), a
      }

      function jh(e) {
         return this.changeBit(e, ms)
      }

      function Xh(e) {
         return this.changeBit(e, rl)
      }

      function Jh(e) {
         return this.changeBit(e, tl)
      }

      function ed(e, t) {
         for (var a = 0, r = 0, n = Math.min(e.t, this.t); a < n;) r += this.data[a] + e.data[a], t.data[a++] = r & this.DM, r >>= this.DB;
         if (e.t < this.t) {
            for (r += e.s; a < this.t;) r += this.data[a], t.data[a++] = r & this.DM, r >>= this.DB;
            r += this.s
         } else {
            for (r += this.s; a < e.t;) r += e.data[a], t.data[a++] = r & this.DM, r >>= this.DB;
            r += e.s
         }
         t.s = r < 0 ? -1 : 0, r > 0 ? t.data[a++] = r : r < -1 && (t.data[a++] = this.DV + r), t.t = a, t.clamp()
      }

      function td(e) {
         var t = ne();
         return this.addTo(e, t), t
      }

      function rd(e) {
         var t = ne();
         return this.subTo(e, t), t
      }

      function ad(e) {
         var t = ne();
         return this.multiplyTo(e, t), t
      }

      function nd(e) {
         var t = ne();
         return this.divRemTo(e, t, null), t
      }

      function id(e) {
         var t = ne();
         return this.divRemTo(e, null, t), t
      }

      function sd(e) {
         var t = ne(),
            a = ne();
         return this.divRemTo(e, t, a), new Array(t, a)
      }

      function od(e) {
         this.data[this.t] = this.am(0, e - 1, this, 0, 0, this.t), ++this.t, this.clamp()
      }

      function ud(e, t) {
         if (e != 0) {
            for (; this.t <= t;) this.data[this.t++] = 0;
            for (this.data[t] += e; this.data[t] >= this.DV;) this.data[t] -= this.DV, ++t >= this.t && (this.data[this.t++] = 0), ++this.data[t]
         }
      }

      function en() {}

      function al(e) {
         return e
      }

      function ld(e, t, a) {
         e.multiplyTo(t, a)
      }

      function cd(e, t) {
         e.squareTo(t)
      }
      en.prototype.convert = al;
      en.prototype.revert = al;
      en.prototype.mulTo = ld;
      en.prototype.sqrTo = cd;

      function fd(e) {
         return this.exp(e, new en)
      }

      function hd(e, t, a) {
         var r = Math.min(this.t + e.t, t);
         for (a.s = 0, a.t = r; r > 0;) a.data[--r] = 0;
         var n;
         for (n = a.t - this.t; r < n; ++r) a.data[r + this.t] = this.am(0, e.data[r], a, r, 0, this.t);
         for (n = Math.min(e.t, t); r < n; ++r) this.am(0, e.data[r], a, r, 0, t - r);
         a.clamp()
      }

      function dd(e, t, a) {
         --t;
         var r = a.t = this.t + e.t - t;
         for (a.s = 0; --r >= 0;) a.data[r] = 0;
         for (r = Math.max(t - this.t, 0); r < e.t; ++r) a.data[this.t + r - t] = this.am(t - r, e.data[r], a, 0, 0, this.t + r - t);
         a.clamp(), a.drShiftTo(1, a)
      }

      function ra(e) {
         this.r2 = ne(), this.q3 = ne(), w.ONE.dlShiftTo(2 * e.t, this.r2), this.mu = this.r2.divide(e), this.m = e
      }

      function pd(e) {
         if (e.s < 0 || e.t > 2 * this.m.t) return e.mod(this.m);
         if (e.compareTo(this.m) < 0) return e;
         var t = ne();
         return e.copyTo(t), this.reduce(t), t
      }

      function yd(e) {
         return e
      }

      function md(e) {
         for (e.drShiftTo(this.m.t - 1, this.r2), e.t > this.m.t + 1 && (e.t = this.m.t + 1, e.clamp()), this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3), this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2); e.compareTo(this.r2) < 0;) e.dAddOffset(1, this.m.t + 1);
         for (e.subTo(this.r2, e); e.compareTo(this.m) >= 0;) e.subTo(this.m, e)
      }

      function gd(e, t) {
         e.squareTo(t), this.reduce(t)
      }

      function vd(e, t, a) {
         e.multiplyTo(t, a), this.reduce(a)
      }
      ra.prototype.convert = pd;
      ra.prototype.revert = yd;
      ra.prototype.reduce = md;
      ra.prototype.mulTo = vd;
      ra.prototype.sqrTo = gd;

      function Ed(e, t) {
         var a = e.bitLength(),
            r, n = ur(1),
            i;
         if (a <= 0) return n;
         a < 18 ? r = 1 : a < 48 ? r = 3 : a < 144 ? r = 4 : a < 768 ? r = 5 : r = 6, a < 8 ? i = new Ir(t) : t.isEven() ? i = new ra(t) : i = new br(t);
         var s = new Array,
            o = 3,
            u = r - 1,
            l = (1 << r) - 1;
         if (s[1] = i.convert(this), r > 1) {
            var c = ne();
            for (i.sqrTo(s[1], c); o <= l;) s[o] = ne(), i.mulTo(c, s[o - 2], s[o]), o += 2
         }
         var f = e.t - 1,
            y, g = !0,
            m = ne(),
            x;
         for (a = Zn(e.data[f]) - 1; f >= 0;) {
            for (a >= u ? y = e.data[f] >> a - u & l : (y = (e.data[f] & (1 << a + 1) - 1) << u - a, f > 0 && (y |= e.data[f - 1] >> this.DB + a - u)), o = r; !(y & 1);) y >>= 1, --o;
            if ((a -= o) < 0 && (a += this.DB, --f), g) s[y].copyTo(n), g = !1;
            else {
               for (; o > 1;) i.sqrTo(n, m), i.sqrTo(m, n), o -= 2;
               o > 0 ? i.sqrTo(n, m) : (x = n, n = m, m = x), i.mulTo(m, s[y], n)
            }
            for (; f >= 0 && !(e.data[f] & 1 << a);) i.sqrTo(n, m), x = n, n = m, m = x, --a < 0 && (a = this.DB - 1, --f)
         }
         return i.revert(n)
      }

      function Cd(e) {
         var t = this.s < 0 ? this.negate() : this.clone(),
            a = e.s < 0 ? e.negate() : e.clone();
         if (t.compareTo(a) < 0) {
            var r = t;
            t = a, a = r
         }
         var n = t.getLowestSetBit(),
            i = a.getLowestSetBit();
         if (i < 0) return t;
         for (n < i && (i = n), i > 0 && (t.rShiftTo(i, t), a.rShiftTo(i, a)); t.signum() > 0;)(n = t.getLowestSetBit()) > 0 && t.rShiftTo(n, t), (n = a.getLowestSetBit()) > 0 && a.rShiftTo(n, a), t.compareTo(a) >= 0 ? (t.subTo(a, t), t.rShiftTo(1, t)) : (a.subTo(t, a), a.rShiftTo(1, a));
         return i > 0 && a.lShiftTo(i, a), a
      }

      function xd(e) {
         if (e <= 0) return 0;
         var t = this.DV % e,
            a = this.s < 0 ? e - 1 : 0;
         if (this.t > 0)
            if (t == 0) a = this.data[0] % e;
            else
               for (var r = this.t - 1; r >= 0; --r) a = (t * a + this.data[r]) % e;
         return a
      }

      function Td(e) {
         var t = e.isEven();
         if (this.isEven() && t || e.signum() == 0) return w.ZERO;
         for (var a = e.clone(), r = this.clone(), n = ur(1), i = ur(0), s = ur(0), o = ur(1); a.signum() != 0;) {
            for (; a.isEven();) a.rShiftTo(1, a), t ? ((!n.isEven() || !i.isEven()) && (n.addTo(this, n), i.subTo(e, i)), n.rShiftTo(1, n)) : i.isEven() || i.subTo(e, i), i.rShiftTo(1, i);
            for (; r.isEven();) r.rShiftTo(1, r), t ? ((!s.isEven() || !o.isEven()) && (s.addTo(this, s), o.subTo(e, o)), s.rShiftTo(1, s)) : o.isEven() || o.subTo(e, o), o.rShiftTo(1, o);
            a.compareTo(r) >= 0 ? (a.subTo(r, a), t && n.subTo(s, n), i.subTo(o, i)) : (r.subTo(a, r), t && s.subTo(n, s), o.subTo(i, o))
         }
         if (r.compareTo(w.ONE) != 0) return w.ZERO;
         if (o.compareTo(e) >= 0) return o.subtract(e);
         if (o.signum() < 0) o.addTo(e, o);
         else return o;
         return o.signum() < 0 ? o.add(e) : o
      }
      var Nt = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509],
         Sd = (1 << 26) / Nt[Nt.length - 1];

      function Id(e) {
         var t, a = this.abs();
         if (a.t == 1 && a.data[0] <= Nt[Nt.length - 1]) {
            for (t = 0; t < Nt.length; ++t)
               if (a.data[0] == Nt[t]) return !0;
            return !1
         }
         if (a.isEven()) return !1;
         for (t = 1; t < Nt.length;) {
            for (var r = Nt[t], n = t + 1; n < Nt.length && r < Sd;) r *= Nt[n++];
            for (r = a.modInt(r); t < n;)
               if (r % Nt[t++] == 0) return !1
         }
         return a.millerRabin(e)
      }

      function bd(e) {
         var t = this.subtract(w.ONE),
            a = t.getLowestSetBit();
         if (a <= 0) return !1;
         for (var r = t.shiftRight(a), n = Ad(), i, s = 0; s < e; ++s) {
            do i = new w(this.bitLength(), n); while (i.compareTo(w.ONE) <= 0 || i.compareTo(t) >= 0);
            var o = i.modPow(r, this);
            if (o.compareTo(w.ONE) != 0 && o.compareTo(t) != 0) {
               for (var u = 1; u++ < a && o.compareTo(t) != 0;)
                  if (o = o.modPowInt(2, this), o.compareTo(w.ONE) == 0) return !1;
               if (o.compareTo(t) != 0) return !1
            }
         }
         return !0
      }

      function Ad() {
         return {
            nextBytes: function(e) {
               for (var t = 0; t < e.length; ++t) e[t] = Math.floor(Math.random() * 256)
            }
         }
      }
      w.prototype.chunkSize = Bh;
      w.prototype.toRadix = Nh;
      w.prototype.fromRadix = _h;
      w.prototype.fromNumber = Dh;
      w.prototype.bitwiseTo = Uh;
      w.prototype.changeBit = $h;
      w.prototype.addTo = ed;
      w.prototype.dMultiply = od;
      w.prototype.dAddOffset = ud;
      w.prototype.multiplyLowerTo = hd;
      w.prototype.multiplyUpperTo = dd;
      w.prototype.modInt = xd;
      w.prototype.millerRabin = bd;
      w.prototype.clone = Sh;
      w.prototype.intValue = Ih;
      w.prototype.byteValue = bh;
      w.prototype.shortValue = Ah;
      w.prototype.signum = wh;
      w.prototype.toByteArray = Rh;
      w.prototype.equals = Lh;
      w.prototype.min = kh;
      w.prototype.max = Oh;
      w.prototype.and = Ph;
      w.prototype.or = Vh;
      w.prototype.xor = Mh;
      w.prototype.andNot = Kh;
      w.prototype.not = qh;
      w.prototype.shiftLeft = Hh;
      w.prototype.shiftRight = Gh;
      w.prototype.getLowestSetBit = Wh;
      w.prototype.bitCount = Zh;
      w.prototype.testBit = Qh;
      w.prototype.setBit = jh;
      w.prototype.clearBit = Xh;
      w.prototype.flipBit = Jh;
      w.prototype.add = td;
      w.prototype.subtract = rd;
      w.prototype.multiply = ad;
      w.prototype.divide = nd;
      w.prototype.remainder = id;
      w.prototype.divideAndRemainder = sd;
      w.prototype.modPow = Ed;
      w.prototype.modInverse = Td;
      w.prototype.pow = fd;
      w.prototype.gcd = Cd;
      w.prototype.isProbablePrime = Id
   });
   var aa = Y((Ag, ul) => {
      "use strict";
      var Ft = $();
      Rt();
      ae();
      var sl = ul.exports = Ft.sha1 = Ft.sha1 || {};
      Ft.md.sha1 = Ft.md.algorithms.sha1 = sl;
      sl.create = function() {
         ol || Bd();
         var e = null,
            t = Ft.util.createBuffer(),
            a = new Array(80),
            r = {
               algorithm: "sha1",
               blockLength: 64,
               digestLength: 20,
               messageLength: 0,
               fullMessageLength: null,
               messageLengthSize: 8
            };
         return r.start = function() {
            r.messageLength = 0, r.fullMessageLength = r.messageLength64 = [];
            for (var n = r.messageLengthSize / 4, i = 0; i < n; ++i) r.fullMessageLength.push(0);
            return t = Ft.util.createBuffer(), e = {
               h0: 1732584193,
               h1: 4023233417,
               h2: 2562383102,
               h3: 271733878,
               h4: 3285377520
            }, r
         }, r.start(), r.update = function(n, i) {
            i === "utf8" && (n = Ft.util.encodeUtf8(n));
            var s = n.length;
            r.messageLength += s, s = [s / 4294967296 >>> 0, s >>> 0];
            for (var o = r.fullMessageLength.length - 1; o >= 0; --o) r.fullMessageLength[o] += s[1], s[1] = s[0] + (r.fullMessageLength[o] / 4294967296 >>> 0), r.fullMessageLength[o] = r.fullMessageLength[o] >>> 0, s[0] = s[1] / 4294967296 >>> 0;
            return t.putBytes(n), il(e, a, t), (t.read > 2048 || t.length() === 0) && t.compact(), r
         }, r.digest = function() {
            var n = Ft.util.createBuffer();
            n.putBytes(t.bytes());
            var i = r.fullMessageLength[r.fullMessageLength.length - 1] + r.messageLengthSize,
               s = i & r.blockLength - 1;
            n.putBytes(gs.substr(0, r.blockLength - s));
            for (var o, u, l = r.fullMessageLength[0] * 8, c = 0; c < r.fullMessageLength.length - 1; ++c) o = r.fullMessageLength[c + 1] * 8, u = o / 4294967296 >>> 0, l += u, n.putInt32(l >>> 0), l = o >>> 0;
            n.putInt32(l);
            var f = {
               h0: e.h0,
               h1: e.h1,
               h2: e.h2,
               h3: e.h3,
               h4: e.h4
            };
            il(f, a, n);
            var y = Ft.util.createBuffer();
            return y.putInt32(f.h0), y.putInt32(f.h1), y.putInt32(f.h2), y.putInt32(f.h3), y.putInt32(f.h4), y
         }, r
      };
      var gs = null,
         ol = !1;

      function Bd() {
         gs = String.fromCharCode(128), gs += Ft.util.fillString(String.fromCharCode(0), 64), ol = !0
      }

      function il(e, t, a) {
         for (var r, n, i, s, o, u, l, c, f = a.length(); f >= 64;) {
            for (n = e.h0, i = e.h1, s = e.h2, o = e.h3, u = e.h4, c = 0; c < 16; ++c) r = a.getInt32(), t[c] = r, l = o ^ i & (s ^ o), r = (n << 5 | n >>> 27) + l + u + 1518500249 + r, u = o, o = s, s = (i << 30 | i >>> 2) >>> 0, i = n, n = r;
            for (; c < 20; ++c) r = t[c - 3] ^ t[c - 8] ^ t[c - 14] ^ t[c - 16], r = r << 1 | r >>> 31, t[c] = r, l = o ^ i & (s ^ o), r = (n << 5 | n >>> 27) + l + u + 1518500249 + r, u = o, o = s, s = (i << 30 | i >>> 2) >>> 0, i = n, n = r;
            for (; c < 32; ++c) r = t[c - 3] ^ t[c - 8] ^ t[c - 14] ^ t[c - 16], r = r << 1 | r >>> 31, t[c] = r, l = i ^ s ^ o, r = (n << 5 | n >>> 27) + l + u + 1859775393 + r, u = o, o = s, s = (i << 30 | i >>> 2) >>> 0, i = n, n = r;
            for (; c < 40; ++c) r = t[c - 6] ^ t[c - 16] ^ t[c - 28] ^ t[c - 32], r = r << 2 | r >>> 30, t[c] = r, l = i ^ s ^ o, r = (n << 5 | n >>> 27) + l + u + 1859775393 + r, u = o, o = s, s = (i << 30 | i >>> 2) >>> 0, i = n, n = r;
            for (; c < 60; ++c) r = t[c - 6] ^ t[c - 16] ^ t[c - 28] ^ t[c - 32], r = r << 2 | r >>> 30, t[c] = r, l = i & s | o & (i ^ s), r = (n << 5 | n >>> 27) + l + u + 2400959708 + r, u = o, o = s, s = (i << 30 | i >>> 2) >>> 0, i = n, n = r;
            for (; c < 80; ++c) r = t[c - 6] ^ t[c - 16] ^ t[c - 28] ^ t[c - 32], r = r << 2 | r >>> 30, t[c] = r, l = i ^ s ^ o, r = (n << 5 | n >>> 27) + l + u + 3395469782 + r, u = o, o = s, s = (i << 30 | i >>> 2) >>> 0, i = n, n = r;
            e.h0 = e.h0 + n | 0, e.h1 = e.h1 + i | 0, e.h2 = e.h2 + s | 0, e.h3 = e.h3 + o | 0, e.h4 = e.h4 + u | 0, f -= 64
         }
      }
   });
   var vs = Y((Bg, cl) => {
      "use strict";
      var Pt = $();
      ae();
      mt();
      aa();
      var ll = cl.exports = Pt.pkcs1 = Pt.pkcs1 || {};
      ll.encode_rsa_oaep = function(e, t, a) {
         var r, n, i, s;
         typeof a == "string" ? (r = a, n = arguments[3] || void 0, i = arguments[4] || void 0) : a && (r = a.label || void 0, n = a.seed || void 0, i = a.md || void 0, a.mgf1 && a.mgf1.md && (s = a.mgf1.md)), i ? i.start() : i = Pt.md.sha1.create(), s || (s = i);
         var o = Math.ceil(e.n.bitLength() / 8),
            u = o - 2 * i.digestLength - 2;
         if (t.length > u) {
            var l = new Error("RSAES-OAEP input message length is too long.");
            throw l.length = t.length, l.maxLength = u, l
         }
         r || (r = ""), i.update(r, "raw");
         for (var c = i.digest(), f = "", y = u - t.length, g = 0; g < y; g++) f += "\0";
         var m = c.getBytes() + f + "" + t;
         if (!n) n = Pt.random.getBytes(i.digestLength);
         else if (n.length !== i.digestLength) {
            var l = new Error("Invalid RSAES-OAEP seed. The seed length must match the digest length.");
            throw l.seedLength = n.length, l.digestLength = i.digestLength, l
         }
         var x = Qn(n, o - i.digestLength - 1, s),
            T = Pt.util.xorBytes(m, x, m.length),
            I = Qn(T, i.digestLength, s),
            A = Pt.util.xorBytes(n, I, n.length);
         return "\0" + A + T
      };
      ll.decode_rsa_oaep = function(e, t, a) {
         var r, n, i;
         typeof a == "string" ? (r = a, n = arguments[3] || void 0) : a && (r = a.label || void 0, n = a.md || void 0, a.mgf1 && a.mgf1.md && (i = a.mgf1.md));
         var s = Math.ceil(e.n.bitLength() / 8);
         if (t.length !== s) {
            var T = new Error("RSAES-OAEP encoded message length is invalid.");
            throw T.length = t.length, T.expectedLength = s, T
         }
         if (n === void 0 ? n = Pt.md.sha1.create() : n.start(), i || (i = n), s < 2 * n.digestLength + 2) throw new Error("RSAES-OAEP key is too short for the hash function.");
         r || (r = ""), n.update(r, "raw");
         for (var o = n.digest().getBytes(), u = t.charAt(0), l = t.substring(1, n.digestLength + 1), c = t.substring(1 + n.digestLength), f = Qn(c, n.digestLength, i), y = Pt.util.xorBytes(l, f, l.length), g = Qn(y, s - n.digestLength - 1, i), m = Pt.util.xorBytes(c, g, c.length), x = m.substring(0, n.digestLength), T = u !== "\0", I = 0; I < n.digestLength; ++I) T |= o.charAt(I) !== x.charAt(I);
         for (var A = 1, B = n.digestLength, F = n.digestLength; F < m.length; F++) {
            var R = m.charCodeAt(F),
               D = R & 1 ^ 1,
               G = A ? 65534 : 0;
            T |= R & G, A = A & D, B += A
         }
         if (T || m.charCodeAt(B) !== 1) throw new Error("Invalid RSAES-OAEP padding.");
         return m.substring(B + 1)
      };

      function Qn(e, t, a) {
         a || (a = Pt.md.sha1.create());
         for (var r = "", n = Math.ceil(t / a.digestLength), i = 0; i < n; ++i) {
            var s = String.fromCharCode(i >> 24 & 255, i >> 16 & 255, i >> 8 & 255, i & 255);
            a.start(), a.update(e + s), r += a.digest().getBytes()
         }
         return r.substring(0, t)
      }
   });
   var Cs = Y((wg, Es) => {
      "use strict";
      var lr = $();
      ae();
      tn();
      mt();
      (function() {
         if (lr.prime) {
            Es.exports = lr.prime;
            return
         }
         var e = Es.exports = lr.prime = lr.prime || {},
            t = lr.jsbn.BigInteger,
            a = [6, 4, 2, 4, 2, 4, 6, 2],
            r = new t(null);
         r.fromInt(30);
         var n = function(f, y) {
            return f | y
         };
         e.generateProbablePrime = function(f, y, g) {
            typeof y == "function" && (g = y, y = {}), y = y || {};
            var m = y.algorithm || "PRIMEINC";
            typeof m == "string" && (m = {
               name: m
            }), m.options = m.options || {};
            var x = y.prng || lr.random,
               T = {
                  nextBytes: function(I) {
                     for (var A = x.getBytesSync(I.length), B = 0; B < I.length; ++B) I[B] = A.charCodeAt(B)
                  }
               };
            if (m.name === "PRIMEINC") return i(f, T, m.options, g);
            throw new Error("Invalid prime generation algorithm: " + m.name)
         };

         function i(f, y, g, m) {
            return "workers" in g ? u(f, y, g, m) : s(f, y, g, m)
         }

         function s(f, y, g, m) {
            var x = l(f, y),
               T = 0,
               I = c(x.bitLength());
            "millerRabinTests" in g && (I = g.millerRabinTests);
            var A = 10;
            "maxBlockTime" in g && (A = g.maxBlockTime), o(x, f, y, T, I, A, m)
         }

         function o(f, y, g, m, x, T, I) {
            var A = +new Date;
            do {
               if (f.bitLength() > y && (f = l(y, g)), f.isProbablePrime(x)) return I(null, f);
               f.dAddOffset(a[m++ % 8], 0)
            } while (T < 0 || +new Date - A < T);
            lr.util.setImmediate(function() {
               o(f, y, g, m, x, T, I)
            })
         }

         function u(f, y, g, m) {
            if (typeof Worker > "u") return s(f, y, g, m);
            var x = l(f, y),
               T = g.workers,
               I = g.workLoad || 100,
               A = I * 30 / 8,
               B = g.workerScript || "forge/prime.worker.js";
            if (T === -1) return lr.util.estimateCores(function(R, D) {
               R && (D = 2), T = D - 1, F()
            });
            F();

            function F() {
               T = Math.max(1, T);
               for (var R = [], D = 0; D < T; ++D) R[D] = new Worker(B);
               for (var G = T, D = 0; D < T; ++D) R[D].addEventListener("message", oe);
               var z = !1;

               function oe(ce) {
                  if (!z) {
                     --G;
                     var pe = ce.data;
                     if (pe.found) {
                        for (var ge = 0; ge < R.length; ++ge) R[ge].terminate();
                        return z = !0, m(null, new t(pe.prime, 16))
                     }
                     x.bitLength() > f && (x = l(f, y));
                     var et = x.toString(16);
                     ce.target.postMessage({
                        hex: et,
                        workLoad: I
                     }), x.dAddOffset(A, 0)
                  }
               }
            }
         }

         function l(f, y) {
            var g = new t(f, y),
               m = f - 1;
            return g.testBit(m) || g.bitwiseTo(t.ONE.shiftLeft(m), n, g), g.dAddOffset(31 - g.mod(r).byteValue(), 0), g
         }

         function c(f) {
            return f <= 100 ? 27 : f <= 150 ? 18 : f <= 200 ? 15 : f <= 250 ? 12 : f <= 300 ? 9 : f <= 350 ? 8 : f <= 400 ? 7 : f <= 500 ? 6 : f <= 600 ? 5 : f <= 800 ? 4 : f <= 1250 ? 3 : 2
         }
      })()
   });
   var rn = Y((Ng, gl) => {
      "use strict";
      var K = $();
      wt();
      tn();
      or();
      vs();
      Cs();
      mt();
      ae();
      typeof te > "u" && (te = K.jsbn.BigInteger);
      var te, xs = K.util.isNodejs ? gn("crypto") : null,
         S = K.asn1,
         vt = K.util;
      K.pki = K.pki || {};
      gl.exports = K.pki.rsa = K.rsa = K.rsa || {};
      var W = K.pki,
         wd = [6, 4, 2, 4, 2, 4, 6, 2],
         Nd = {
            name: "PrivateKeyInfo",
            tagClass: S.Class.UNIVERSAL,
            type: S.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "PrivateKeyInfo.version",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "privateKeyVersion"
            }, {
               name: "PrivateKeyInfo.privateKeyAlgorithm",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.SEQUENCE,
               constructed: !0,
               value: [{
                  name: "AlgorithmIdentifier.algorithm",
                  tagClass: S.Class.UNIVERSAL,
                  type: S.Type.OID,
                  constructed: !1,
                  capture: "privateKeyOid"
               }]
            }, {
               name: "PrivateKeyInfo",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.OCTETSTRING,
               constructed: !1,
               capture: "privateKey"
            }]
         },
         _d = {
            name: "RSAPrivateKey",
            tagClass: S.Class.UNIVERSAL,
            type: S.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "RSAPrivateKey.version",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "privateKeyVersion"
            }, {
               name: "RSAPrivateKey.modulus",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "privateKeyModulus"
            }, {
               name: "RSAPrivateKey.publicExponent",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "privateKeyPublicExponent"
            }, {
               name: "RSAPrivateKey.privateExponent",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "privateKeyPrivateExponent"
            }, {
               name: "RSAPrivateKey.prime1",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "privateKeyPrime1"
            }, {
               name: "RSAPrivateKey.prime2",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "privateKeyPrime2"
            }, {
               name: "RSAPrivateKey.exponent1",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "privateKeyExponent1"
            }, {
               name: "RSAPrivateKey.exponent2",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "privateKeyExponent2"
            }, {
               name: "RSAPrivateKey.coefficient",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "privateKeyCoefficient"
            }]
         },
         Dd = {
            name: "RSAPublicKey",
            tagClass: S.Class.UNIVERSAL,
            type: S.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "RSAPublicKey.modulus",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "publicKeyModulus"
            }, {
               name: "RSAPublicKey.exponent",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.INTEGER,
               constructed: !1,
               capture: "publicKeyExponent"
            }]
         },
         Rd = K.pki.rsa.publicKeyValidator = {
            name: "SubjectPublicKeyInfo",
            tagClass: S.Class.UNIVERSAL,
            type: S.Type.SEQUENCE,
            constructed: !0,
            captureAsn1: "subjectPublicKeyInfo",
            value: [{
               name: "SubjectPublicKeyInfo.AlgorithmIdentifier",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.SEQUENCE,
               constructed: !0,
               value: [{
                  name: "AlgorithmIdentifier.algorithm",
                  tagClass: S.Class.UNIVERSAL,
                  type: S.Type.OID,
                  constructed: !1,
                  capture: "publicKeyOid"
               }]
            }, {
               name: "SubjectPublicKeyInfo.subjectPublicKey",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.BITSTRING,
               constructed: !1,
               value: [{
                  name: "SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey",
                  tagClass: S.Class.UNIVERSAL,
                  type: S.Type.SEQUENCE,
                  constructed: !0,
                  optional: !0,
                  captureAsn1: "rsaPublicKey"
               }]
            }]
         },
         Ld = {
            name: "DigestInfo",
            tagClass: S.Class.UNIVERSAL,
            type: S.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "DigestInfo.DigestAlgorithm",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.SEQUENCE,
               constructed: !0,
               value: [{
                  name: "DigestInfo.DigestAlgorithm.algorithmIdentifier",
                  tagClass: S.Class.UNIVERSAL,
                  type: S.Type.OID,
                  constructed: !1,
                  capture: "algorithmIdentifier"
               }, {
                  name: "DigestInfo.DigestAlgorithm.parameters",
                  tagClass: S.Class.UNIVERSAL,
                  type: S.Type.NULL,
                  capture: "parameters",
                  optional: !0,
                  constructed: !1
               }]
            }, {
               name: "DigestInfo.digest",
               tagClass: S.Class.UNIVERSAL,
               type: S.Type.OCTETSTRING,
               constructed: !1,
               capture: "digest"
            }]
         },
         kd = function(e) {
            var t;
            if (e.algorithm in W.oids) t = W.oids[e.algorithm];
            else {
               var a = new Error("Unknown message digest algorithm.");
               throw a.algorithm = e.algorithm, a
            }
            var r = S.oidToDer(t).getBytes(),
               n = S.create(S.Class.UNIVERSAL, S.Type.SEQUENCE, !0, []),
               i = S.create(S.Class.UNIVERSAL, S.Type.SEQUENCE, !0, []);
            i.value.push(S.create(S.Class.UNIVERSAL, S.Type.OID, !1, r)), i.value.push(S.create(S.Class.UNIVERSAL, S.Type.NULL, !1, ""));
            var s = S.create(S.Class.UNIVERSAL, S.Type.OCTETSTRING, !1, e.digest().getBytes());
            return n.value.push(i), n.value.push(s), S.toDer(n).getBytes()
         },
         yl = function(e, t, a) {
            if (a) return e.modPow(t.e, t.n);
            if (!t.p || !t.q) return e.modPow(t.d, t.n);
            t.dP || (t.dP = t.d.mod(t.p.subtract(te.ONE))), t.dQ || (t.dQ = t.d.mod(t.q.subtract(te.ONE))), t.qInv || (t.qInv = t.q.modInverse(t.p));
            var r;
            do r = new te(K.util.bytesToHex(K.random.getBytes(t.n.bitLength() / 8)), 16); while (r.compareTo(t.n) >= 0 || !r.gcd(t.n).equals(te.ONE));
            e = e.multiply(r.modPow(t.e, t.n)).mod(t.n);
            for (var n = e.mod(t.p).modPow(t.dP, t.p), i = e.mod(t.q).modPow(t.dQ, t.q); n.compareTo(i) < 0;) n = n.add(t.p);
            var s = n.subtract(i).multiply(t.qInv).mod(t.p).multiply(t.q).add(i);
            return s = s.multiply(r.modInverse(t.n)).mod(t.n), s
         };
      W.rsa.encrypt = function(e, t, a) {
         var r = a,
            n, i = Math.ceil(t.n.bitLength() / 8);
         a !== !1 && a !== !0 ? (r = a === 2, n = ml(e, t, a)) : (n = K.util.createBuffer(), n.putBytes(e));
         for (var s = new te(n.toHex(), 16), o = yl(s, t, r), u = o.toString(16), l = K.util.createBuffer(), c = i - Math.ceil(u.length / 2); c > 0;) l.putByte(0), --c;
         return l.putBytes(K.util.hexToBytes(u)), l.getBytes()
      };
      W.rsa.decrypt = function(e, t, a, r) {
         var n = Math.ceil(t.n.bitLength() / 8);
         if (e.length !== n) {
            var i = new Error("Encrypted message length is invalid.");
            throw i.length = e.length, i.expected = n, i
         }
         var s = new te(K.util.createBuffer(e).toHex(), 16);
         if (s.compareTo(t.n) >= 0) throw new Error("Encrypted message is invalid.");
         for (var o = yl(s, t, a), u = o.toString(16), l = K.util.createBuffer(), c = n - Math.ceil(u.length / 2); c > 0;) l.putByte(0), --c;
         return l.putBytes(K.util.hexToBytes(u)), r !== !1 ? $n(l.getBytes(), t, a) : l.getBytes()
      };
      W.rsa.createKeyPairGenerationState = function(e, t, a) {
         typeof e == "string" && (e = parseInt(e, 10)), e = e || 2048, a = a || {};
         var r = a.prng || K.random,
            n = {
               nextBytes: function(o) {
                  for (var u = r.getBytesSync(o.length), l = 0; l < o.length; ++l) o[l] = u.charCodeAt(l)
               }
            },
            i = a.algorithm || "PRIMEINC",
            s;
         if (i === "PRIMEINC") s = {
            algorithm: i,
            state: 0,
            bits: e,
            rng: n,
            eInt: t || 65537,
            e: new te(null),
            p: null,
            q: null,
            qBits: e >> 1,
            pBits: e - (e >> 1),
            pqState: 0,
            num: null,
            keys: null
         }, s.e.fromInt(s.eInt);
         else throw new Error("Invalid key generation algorithm: " + i);
         return s
      };
      W.rsa.stepKeyPairGenerationState = function(e, t) {
         "algorithm" in e || (e.algorithm = "PRIMEINC");
         var a = new te(null);
         a.fromInt(30);
         for (var r = 0, n = function(f, y) {
               return f | y
            }, i = +new Date, s, o = 0; e.keys === null && (t <= 0 || o < t);) {
            if (e.state === 0) {
               var u = e.p === null ? e.pBits : e.qBits,
                  l = u - 1;
               e.pqState === 0 ? (e.num = new te(u, e.rng), e.num.testBit(l) || e.num.bitwiseTo(te.ONE.shiftLeft(l), n, e.num), e.num.dAddOffset(31 - e.num.mod(a).byteValue(), 0), r = 0, ++e.pqState) : e.pqState === 1 ? e.num.bitLength() > u ? e.pqState = 0 : e.num.isProbablePrime(Ud(e.num.bitLength())) ? ++e.pqState : e.num.dAddOffset(wd[r++ % 8], 0) : e.pqState === 2 ? e.pqState = e.num.subtract(te.ONE).gcd(e.e).compareTo(te.ONE) === 0 ? 3 : 0 : e.pqState === 3 && (e.pqState = 0, e.p === null ? e.p = e.num : e.q = e.num, e.p !== null && e.q !== null && ++e.state, e.num = null)
            } else if (e.state === 1) e.p.compareTo(e.q) < 0 && (e.num = e.p, e.p = e.q, e.q = e.num), ++e.state;
            else if (e.state === 2) e.p1 = e.p.subtract(te.ONE), e.q1 = e.q.subtract(te.ONE), e.phi = e.p1.multiply(e.q1), ++e.state;
            else if (e.state === 3) e.phi.gcd(e.e).compareTo(te.ONE) === 0 ? ++e.state : (e.p = null, e.q = null, e.state = 0);
            else if (e.state === 4) e.n = e.p.multiply(e.q), e.n.bitLength() === e.bits ? ++e.state : (e.q = null, e.state = 0);
            else if (e.state === 5) {
               var c = e.e.modInverse(e.phi);
               e.keys = {
                  privateKey: W.rsa.setPrivateKey(e.n, e.e, c, e.p, e.q, c.mod(e.p1), c.mod(e.q1), e.q.modInverse(e.p)),
                  publicKey: W.rsa.setPublicKey(e.n, e.e)
               }
            }
            s = +new Date, o += s - i, i = s
         }
         return e.keys !== null
      };
      W.rsa.generateKeyPair = function(e, t, a, r) {
         if (arguments.length === 1 ? typeof e == "object" ? (a = e, e = void 0) : typeof e == "function" && (r = e, e = void 0) : arguments.length === 2 ? typeof e == "number" ? typeof t == "function" ? (r = t, t = void 0) : typeof t != "number" && (a = t, t = void 0) : (a = e, r = t, e = void 0, t = void 0) : arguments.length === 3 && (typeof t == "number" ? typeof a == "function" && (r = a, a = void 0) : (r = a, a = t, t = void 0)), a = a || {}, e === void 0 && (e = a.bits || 2048), t === void 0 && (t = a.e || 65537), !K.options.usePureJavaScript && !a.prng && e >= 256 && e <= 16384 && (t === 65537 || t === 3)) {
            if (r) {
               if (fl("generateKeyPair")) return xs.generateKeyPair("rsa", {
                  modulusLength: e,
                  publicExponent: t,
                  publicKeyEncoding: {
                     type: "spki",
                     format: "pem"
                  },
                  privateKeyEncoding: {
                     type: "pkcs8",
                     format: "pem"
                  }
               }, function(o, u, l) {
                  if (o) return r(o);
                  r(null, {
                     privateKey: W.privateKeyFromPem(l),
                     publicKey: W.publicKeyFromPem(u)
                  })
               });
               if (hl("generateKey") && hl("exportKey")) return vt.globalScope.crypto.subtle.generateKey({
                  name: "RSASSA-PKCS1-v1_5",
                  modulusLength: e,
                  publicExponent: pl(t),
                  hash: {
                     name: "SHA-256"
                  }
               }, !0, ["sign", "verify"]).then(function(o) {
                  return vt.globalScope.crypto.subtle.exportKey("pkcs8", o.privateKey)
               }).then(void 0, function(o) {
                  r(o)
               }).then(function(o) {
                  if (o) {
                     var u = W.privateKeyFromAsn1(S.fromDer(K.util.createBuffer(o)));
                     r(null, {
                        privateKey: u,
                        publicKey: W.setRsaPublicKey(u.n, u.e)
                     })
                  }
               });
               if (dl("generateKey") && dl("exportKey")) {
                  var n = vt.globalScope.msCrypto.subtle.generateKey({
                     name: "RSASSA-PKCS1-v1_5",
                     modulusLength: e,
                     publicExponent: pl(t),
                     hash: {
                        name: "SHA-256"
                     }
                  }, !0, ["sign", "verify"]);
                  n.oncomplete = function(o) {
                     var u = o.target.result,
                        l = vt.globalScope.msCrypto.subtle.exportKey("pkcs8", u.privateKey);
                     l.oncomplete = function(c) {
                        var f = c.target.result,
                           y = W.privateKeyFromAsn1(S.fromDer(K.util.createBuffer(f)));
                        r(null, {
                           privateKey: y,
                           publicKey: W.setRsaPublicKey(y.n, y.e)
                        })
                     }, l.onerror = function(c) {
                        r(c)
                     }
                  }, n.onerror = function(o) {
                     r(o)
                  };
                  return
               }
            } else if (fl("generateKeyPairSync")) {
               var i = xs.generateKeyPairSync("rsa", {
                  modulusLength: e,
                  publicExponent: t,
                  publicKeyEncoding: {
                     type: "spki",
                     format: "pem"
                  },
                  privateKeyEncoding: {
                     type: "pkcs8",
                     format: "pem"
                  }
               });
               return {
                  privateKey: W.privateKeyFromPem(i.privateKey),
                  publicKey: W.publicKeyFromPem(i.publicKey)
               }
            }
         }
         var s = W.rsa.createKeyPairGenerationState(e, t, a);
         if (!r) return W.rsa.stepKeyPairGenerationState(s, 0), s.keys;
         Od(s, a, r)
      };
      W.setRsaPublicKey = W.rsa.setPublicKey = function(e, t) {
         var a = {
            n: e,
            e: t
         };
         return a.encrypt = function(r, n, i) {
            if (typeof n == "string" ? n = n.toUpperCase() : n === void 0 && (n = "RSAES-PKCS1-V1_5"), n === "RSAES-PKCS1-V1_5") n = {
               encode: function(o, u, l) {
                  return ml(o, u, 2).getBytes()
               }
            };
            else if (n === "RSA-OAEP" || n === "RSAES-OAEP") n = {
               encode: function(o, u) {
                  return K.pkcs1.encode_rsa_oaep(u, o, i)
               }
            };
            else if (["RAW", "NONE", "NULL", null].indexOf(n) !== -1) n = {
               encode: function(o) {
                  return o
               }
            };
            else if (typeof n == "string") throw new Error('Unsupported encryption scheme: "' + n + '".');
            var s = n.encode(r, a, !0);
            return W.rsa.encrypt(s, a, !0)
         }, a.verify = function(r, n, i, s) {
            typeof i == "string" ? i = i.toUpperCase() : i === void 0 && (i = "RSASSA-PKCS1-V1_5"), s === void 0 && (s = {
               _parseAllDigestBytes: !0
            }), "_parseAllDigestBytes" in s || (s._parseAllDigestBytes = !0), i === "RSASSA-PKCS1-V1_5" ? i = {
               verify: function(u, l) {
                  l = $n(l, a, !0);
                  var c = S.fromDer(l, {
                        parseAllBytes: s._parseAllDigestBytes
                     }),
                     f = {},
                     y = [];
                  if (!S.validate(c, Ld, f, y)) {
                     var g = new Error("ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 DigestInfo value.");
                     throw g.errors = y, g
                  }
                  var m = S.derToOid(f.algorithmIdentifier);
                  if (!(m === K.oids.md2 || m === K.oids.md5 || m === K.oids.sha1 || m === K.oids.sha224 || m === K.oids.sha256 || m === K.oids.sha384 || m === K.oids.sha512 || m === K.oids["sha512-224"] || m === K.oids["sha512-256"])) {
                     var g = new Error("Unknown RSASSA-PKCS1-v1_5 DigestAlgorithm identifier.");
                     throw g.oid = m, g
                  }
                  if ((m === K.oids.md2 || m === K.oids.md5) && !("parameters" in f)) throw new Error("ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 DigestInfo value. Missing algorithm identifer NULL parameters.");
                  return u === f.digest
               }
            } : (i === "NONE" || i === "NULL" || i === null) && (i = {
               verify: function(u, l) {
                  return l = $n(l, a, !0), u === l
               }
            });
            var o = W.rsa.decrypt(n, a, !0, !1);
            return i.verify(r, o, a.n.bitLength())
         }, a
      };
      W.setRsaPrivateKey = W.rsa.setPrivateKey = function(e, t, a, r, n, i, s, o) {
         var u = {
            n: e,
            e: t,
            d: a,
            p: r,
            q: n,
            dP: i,
            dQ: s,
            qInv: o
         };
         return u.decrypt = function(l, c, f) {
            typeof c == "string" ? c = c.toUpperCase() : c === void 0 && (c = "RSAES-PKCS1-V1_5");
            var y = W.rsa.decrypt(l, u, !1, !1);
            if (c === "RSAES-PKCS1-V1_5") c = {
               decode: $n
            };
            else if (c === "RSA-OAEP" || c === "RSAES-OAEP") c = {
               decode: function(g, m) {
                  return K.pkcs1.decode_rsa_oaep(m, g, f)
               }
            };
            else if (["RAW", "NONE", "NULL", null].indexOf(c) !== -1) c = {
               decode: function(g) {
                  return g
               }
            };
            else throw new Error('Unsupported encryption scheme: "' + c + '".');
            return c.decode(y, u, !1)
         }, u.sign = function(l, c) {
            var f = !1;
            typeof c == "string" && (c = c.toUpperCase()), c === void 0 || c === "RSASSA-PKCS1-V1_5" ? (c = {
               encode: kd
            }, f = 1) : (c === "NONE" || c === "NULL" || c === null) && (c = {
               encode: function() {
                  return l
               }
            }, f = 1);
            var y = c.encode(l, u.n.bitLength());
            return W.rsa.encrypt(y, u, f)
         }, u
      };
      W.wrapRsaPrivateKey = function(e) {
         return S.create(S.Class.UNIVERSAL, S.Type.SEQUENCE, !0, [S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, S.integerToDer(0).getBytes()), S.create(S.Class.UNIVERSAL, S.Type.SEQUENCE, !0, [S.create(S.Class.UNIVERSAL, S.Type.OID, !1, S.oidToDer(W.oids.rsaEncryption).getBytes()), S.create(S.Class.UNIVERSAL, S.Type.NULL, !1, "")]), S.create(S.Class.UNIVERSAL, S.Type.OCTETSTRING, !1, S.toDer(e).getBytes())])
      };
      W.privateKeyFromAsn1 = function(e) {
         var t = {},
            a = [];
         if (S.validate(e, Nd, t, a) && (e = S.fromDer(K.util.createBuffer(t.privateKey))), t = {}, a = [], !S.validate(e, _d, t, a)) {
            var r = new Error("Cannot read private key. ASN.1 object does not contain an RSAPrivateKey.");
            throw r.errors = a, r
         }
         var n, i, s, o, u, l, c, f;
         return n = K.util.createBuffer(t.privateKeyModulus).toHex(), i = K.util.createBuffer(t.privateKeyPublicExponent).toHex(), s = K.util.createBuffer(t.privateKeyPrivateExponent).toHex(), o = K.util.createBuffer(t.privateKeyPrime1).toHex(), u = K.util.createBuffer(t.privateKeyPrime2).toHex(), l = K.util.createBuffer(t.privateKeyExponent1).toHex(), c = K.util.createBuffer(t.privateKeyExponent2).toHex(), f = K.util.createBuffer(t.privateKeyCoefficient).toHex(), W.setRsaPrivateKey(new te(n, 16), new te(i, 16), new te(s, 16), new te(o, 16), new te(u, 16), new te(l, 16), new te(c, 16), new te(f, 16))
      };
      W.privateKeyToAsn1 = W.privateKeyToRSAPrivateKey = function(e) {
         return S.create(S.Class.UNIVERSAL, S.Type.SEQUENCE, !0, [S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, S.integerToDer(0).getBytes()), S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, Vt(e.n)), S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, Vt(e.e)), S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, Vt(e.d)), S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, Vt(e.p)), S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, Vt(e.q)), S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, Vt(e.dP)), S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, Vt(e.dQ)), S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, Vt(e.qInv))])
      };
      W.publicKeyFromAsn1 = function(e) {
         var t = {},
            a = [];
         if (S.validate(e, Rd, t, a)) {
            var r = S.derToOid(t.publicKeyOid);
            if (r !== W.oids.rsaEncryption) {
               var n = new Error("Cannot read public key. Unknown OID.");
               throw n.oid = r, n
            }
            e = t.rsaPublicKey
         }
         if (a = [], !S.validate(e, Dd, t, a)) {
            var n = new Error("Cannot read public key. ASN.1 object does not contain an RSAPublicKey.");
            throw n.errors = a, n
         }
         var i = K.util.createBuffer(t.publicKeyModulus).toHex(),
            s = K.util.createBuffer(t.publicKeyExponent).toHex();
         return W.setRsaPublicKey(new te(i, 16), new te(s, 16))
      };
      W.publicKeyToAsn1 = W.publicKeyToSubjectPublicKeyInfo = function(e) {
         return S.create(S.Class.UNIVERSAL, S.Type.SEQUENCE, !0, [S.create(S.Class.UNIVERSAL, S.Type.SEQUENCE, !0, [S.create(S.Class.UNIVERSAL, S.Type.OID, !1, S.oidToDer(W.oids.rsaEncryption).getBytes()), S.create(S.Class.UNIVERSAL, S.Type.NULL, !1, "")]), S.create(S.Class.UNIVERSAL, S.Type.BITSTRING, !1, [W.publicKeyToRSAPublicKey(e)])])
      };
      W.publicKeyToRSAPublicKey = function(e) {
         return S.create(S.Class.UNIVERSAL, S.Type.SEQUENCE, !0, [S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, Vt(e.n)), S.create(S.Class.UNIVERSAL, S.Type.INTEGER, !1, Vt(e.e))])
      };

      function ml(e, t, a) {
         var r = K.util.createBuffer(),
            n = Math.ceil(t.n.bitLength() / 8);
         if (e.length > n - 11) {
            var i = new Error("Message is too long for PKCS#1 v1.5 padding.");
            throw i.length = e.length, i.max = n - 11, i
         }
         r.putByte(0), r.putByte(a);
         var s = n - 3 - e.length,
            o;
         if (a === 0 || a === 1) {
            o = a === 0 ? 0 : 255;
            for (var u = 0; u < s; ++u) r.putByte(o)
         } else
            for (; s > 0;) {
               for (var l = 0, c = K.random.getBytes(s), u = 0; u < s; ++u) o = c.charCodeAt(u), o === 0 ? ++l : r.putByte(o);
               s = l
            }
         return r.putByte(0), r.putBytes(e), r
      }

      function $n(e, t, a, r) {
         var n = Math.ceil(t.n.bitLength() / 8),
            i = K.util.createBuffer(e),
            s = i.getByte(),
            o = i.getByte();
         if (s !== 0 || a && o !== 0 && o !== 1 || !a && o != 2 || a && o === 0 && typeof r > "u") throw new Error("Encryption block is invalid.");
         var u = 0;
         if (o === 0) {
            u = n - 3 - r;
            for (var l = 0; l < u; ++l)
               if (i.getByte() !== 0) throw new Error("Encryption block is invalid.")
         } else if (o === 1)
            for (u = 0; i.length() > 1;) {
               if (i.getByte() !== 255) {
                  --i.read;
                  break
               }++u
            } else if (o === 2)
               for (u = 0; i.length() > 1;) {
                  if (i.getByte() === 0) {
                     --i.read;
                     break
                  }++u
               }
         var c = i.getByte();
         if (c !== 0 || u !== n - 3 - i.length()) throw new Error("Encryption block is invalid.");
         return i.getBytes()
      }

      function Od(e, t, a) {
         typeof t == "function" && (a = t, t = {}), t = t || {};
         var r = {
            algorithm: {
               name: t.algorithm || "PRIMEINC",
               options: {
                  workers: t.workers || 2,
                  workLoad: t.workLoad || 100,
                  workerScript: t.workerScript
               }
            }
         };
         "prng" in t && (r.prng = t.prng), n();

         function n() {
            i(e.pBits, function(o, u) {
               if (o) return a(o);
               if (e.p = u, e.q !== null) return s(o, e.q);
               i(e.qBits, s)
            })
         }

         function i(o, u) {
            K.prime.generateProbablePrime(o, r, u)
         }

         function s(o, u) {
            if (o) return a(o);
            if (e.q = u, e.p.compareTo(e.q) < 0) {
               var l = e.p;
               e.p = e.q, e.q = l
            }
            if (e.p.subtract(te.ONE).gcd(e.e).compareTo(te.ONE) !== 0) {
               e.p = null, n();
               return
            }
            if (e.q.subtract(te.ONE).gcd(e.e).compareTo(te.ONE) !== 0) {
               e.q = null, i(e.qBits, s);
               return
            }
            if (e.p1 = e.p.subtract(te.ONE), e.q1 = e.q.subtract(te.ONE), e.phi = e.p1.multiply(e.q1), e.phi.gcd(e.e).compareTo(te.ONE) !== 0) {
               e.p = e.q = null, n();
               return
            }
            if (e.n = e.p.multiply(e.q), e.n.bitLength() !== e.bits) {
               e.q = null, i(e.qBits, s);
               return
            }
            var c = e.e.modInverse(e.phi);
            e.keys = {
               privateKey: W.rsa.setPrivateKey(e.n, e.e, c, e.p, e.q, c.mod(e.p1), c.mod(e.q1), e.q.modInverse(e.p)),
               publicKey: W.rsa.setPublicKey(e.n, e.e)
            }, a(null, e.keys)
         }
      }

      function Vt(e) {
         var t = e.toString(16);
         t[0] >= "8" && (t = "00" + t);
         var a = K.util.hexToBytes(t);
         return a.length > 1 && (a.charCodeAt(0) === 0 && !(a.charCodeAt(1) & 128) || a.charCodeAt(0) === 255 && (a.charCodeAt(1) & 128) === 128) ? a.substr(1) : a
      }

      function Ud(e) {
         return e <= 100 ? 27 : e <= 150 ? 18 : e <= 200 ? 15 : e <= 250 ? 12 : e <= 300 ? 9 : e <= 350 ? 8 : e <= 400 ? 7 : e <= 500 ? 6 : e <= 600 ? 5 : e <= 800 ? 4 : e <= 1250 ? 3 : 2
      }

      function fl(e) {
         return K.util.isNodejs && typeof xs[e] == "function"
      }

      function hl(e) {
         return typeof vt.globalScope < "u" && typeof vt.globalScope.crypto == "object" && typeof vt.globalScope.crypto.subtle == "object" && typeof vt.globalScope.crypto.subtle[e] == "function"
      }

      function dl(e) {
         return typeof vt.globalScope < "u" && typeof vt.globalScope.msCrypto == "object" && typeof vt.globalScope.msCrypto.subtle == "object" && typeof vt.globalScope.msCrypto.subtle[e] == "function"
      }

      function pl(e) {
         for (var t = K.util.hexToBytes(e.toString(16)), a = new Uint8Array(t.length), r = 0; r < t.length; ++r) a[r] = t.charCodeAt(r);
         return a
      }
   });
   var Ts = Y((_g, Tl) => {
      "use strict";
      var V = $();
      sr();
      wt();
      Ja();
      Rt();
      or();
      zn();
      Sr();
      mt();
      ds();
      rn();
      ae();
      typeof vl > "u" && (vl = V.jsbn.BigInteger);
      var vl, b = V.asn1,
         Z = V.pki = V.pki || {};
      Tl.exports = Z.pbe = V.pbe = V.pbe || {};
      var Ar = Z.oids,
         Fd = {
            name: "EncryptedPrivateKeyInfo",
            tagClass: b.Class.UNIVERSAL,
            type: b.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "EncryptedPrivateKeyInfo.encryptionAlgorithm",
               tagClass: b.Class.UNIVERSAL,
               type: b.Type.SEQUENCE,
               constructed: !0,
               value: [{
                  name: "AlgorithmIdentifier.algorithm",
                  tagClass: b.Class.UNIVERSAL,
                  type: b.Type.OID,
                  constructed: !1,
                  capture: "encryptionOid"
               }, {
                  name: "AlgorithmIdentifier.parameters",
                  tagClass: b.Class.UNIVERSAL,
                  type: b.Type.SEQUENCE,
                  constructed: !0,
                  captureAsn1: "encryptionParams"
               }]
            }, {
               name: "EncryptedPrivateKeyInfo.encryptedData",
               tagClass: b.Class.UNIVERSAL,
               type: b.Type.OCTETSTRING,
               constructed: !1,
               capture: "encryptedData"
            }]
         },
         Pd = {
            name: "PBES2Algorithms",
            tagClass: b.Class.UNIVERSAL,
            type: b.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "PBES2Algorithms.keyDerivationFunc",
               tagClass: b.Class.UNIVERSAL,
               type: b.Type.SEQUENCE,
               constructed: !0,
               value: [{
                  name: "PBES2Algorithms.keyDerivationFunc.oid",
                  tagClass: b.Class.UNIVERSAL,
                  type: b.Type.OID,
                  constructed: !1,
                  capture: "kdfOid"
               }, {
                  name: "PBES2Algorithms.params",
                  tagClass: b.Class.UNIVERSAL,
                  type: b.Type.SEQUENCE,
                  constructed: !0,
                  value: [{
                     name: "PBES2Algorithms.params.salt",
                     tagClass: b.Class.UNIVERSAL,
                     type: b.Type.OCTETSTRING,
                     constructed: !1,
                     capture: "kdfSalt"
                  }, {
                     name: "PBES2Algorithms.params.iterationCount",
                     tagClass: b.Class.UNIVERSAL,
                     type: b.Type.INTEGER,
                     constructed: !1,
                     capture: "kdfIterationCount"
                  }, {
                     name: "PBES2Algorithms.params.keyLength",
                     tagClass: b.Class.UNIVERSAL,
                     type: b.Type.INTEGER,
                     constructed: !1,
                     optional: !0,
                     capture: "keyLength"
                  }, {
                     name: "PBES2Algorithms.params.prf",
                     tagClass: b.Class.UNIVERSAL,
                     type: b.Type.SEQUENCE,
                     constructed: !0,
                     optional: !0,
                     value: [{
                        name: "PBES2Algorithms.params.prf.algorithm",
                        tagClass: b.Class.UNIVERSAL,
                        type: b.Type.OID,
                        constructed: !1,
                        capture: "prfOid"
                     }]
                  }]
               }]
            }, {
               name: "PBES2Algorithms.encryptionScheme",
               tagClass: b.Class.UNIVERSAL,
               type: b.Type.SEQUENCE,
               constructed: !0,
               value: [{
                  name: "PBES2Algorithms.encryptionScheme.oid",
                  tagClass: b.Class.UNIVERSAL,
                  type: b.Type.OID,
                  constructed: !1,
                  capture: "encOid"
               }, {
                  name: "PBES2Algorithms.encryptionScheme.iv",
                  tagClass: b.Class.UNIVERSAL,
                  type: b.Type.OCTETSTRING,
                  constructed: !1,
                  capture: "encIv"
               }]
            }]
         },
         Vd = {
            name: "pkcs-12PbeParams",
            tagClass: b.Class.UNIVERSAL,
            type: b.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "pkcs-12PbeParams.salt",
               tagClass: b.Class.UNIVERSAL,
               type: b.Type.OCTETSTRING,
               constructed: !1,
               capture: "salt"
            }, {
               name: "pkcs-12PbeParams.iterations",
               tagClass: b.Class.UNIVERSAL,
               type: b.Type.INTEGER,
               constructed: !1,
               capture: "iterations"
            }]
         };
      Z.encryptPrivateKeyInfo = function(e, t, a) {
         a = a || {}, a.saltSize = a.saltSize || 8, a.count = a.count || 2048, a.algorithm = a.algorithm || "aes128", a.prfAlgorithm = a.prfAlgorithm || "sha1";
         var r = V.random.getBytesSync(a.saltSize),
            n = a.count,
            i = b.integerToDer(n),
            s, o, u;
         if (a.algorithm.indexOf("aes") === 0 || a.algorithm === "des") {
            var l, c, f;
            switch (a.algorithm) {
               case "aes128":
                  s = 16, l = 16, c = Ar["aes128-CBC"], f = V.aes.createEncryptionCipher;
                  break;
               case "aes192":
                  s = 24, l = 16, c = Ar["aes192-CBC"], f = V.aes.createEncryptionCipher;
                  break;
               case "aes256":
                  s = 32, l = 16, c = Ar["aes256-CBC"], f = V.aes.createEncryptionCipher;
                  break;
               case "des":
                  s = 8, l = 8, c = Ar.desCBC, f = V.des.createEncryptionCipher;
                  break;
               default:
                  var y = new Error("Cannot encrypt private key. Unknown encryption algorithm.");
                  throw y.algorithm = a.algorithm, y
            }
            var g = "hmacWith" + a.prfAlgorithm.toUpperCase(),
               m = xl(g),
               x = V.pkcs5.pbkdf2(t, r, n, s, m),
               T = V.random.getBytesSync(l),
               I = f(x);
            I.start(T), I.update(b.toDer(e)), I.finish(), u = I.output.getBytes();
            var A = Md(r, i, s, g);
            o = b.create(b.Class.UNIVERSAL, b.Type.SEQUENCE, !0, [b.create(b.Class.UNIVERSAL, b.Type.OID, !1, b.oidToDer(Ar.pkcs5PBES2).getBytes()), b.create(b.Class.UNIVERSAL, b.Type.SEQUENCE, !0, [b.create(b.Class.UNIVERSAL, b.Type.SEQUENCE, !0, [b.create(b.Class.UNIVERSAL, b.Type.OID, !1, b.oidToDer(Ar.pkcs5PBKDF2).getBytes()), A]), b.create(b.Class.UNIVERSAL, b.Type.SEQUENCE, !0, [b.create(b.Class.UNIVERSAL, b.Type.OID, !1, b.oidToDer(c).getBytes()), b.create(b.Class.UNIVERSAL, b.Type.OCTETSTRING, !1, T)])])])
         } else if (a.algorithm === "3des") {
            s = 24;
            var B = new V.util.ByteBuffer(r),
               x = Z.pbe.generatePkcs12Key(t, B, 1, n, s),
               T = Z.pbe.generatePkcs12Key(t, B, 2, n, s),
               I = V.des.createEncryptionCipher(x);
            I.start(T), I.update(b.toDer(e)), I.finish(), u = I.output.getBytes(), o = b.create(b.Class.UNIVERSAL, b.Type.SEQUENCE, !0, [b.create(b.Class.UNIVERSAL, b.Type.OID, !1, b.oidToDer(Ar["pbeWithSHAAnd3-KeyTripleDES-CBC"]).getBytes()), b.create(b.Class.UNIVERSAL, b.Type.SEQUENCE, !0, [b.create(b.Class.UNIVERSAL, b.Type.OCTETSTRING, !1, r), b.create(b.Class.UNIVERSAL, b.Type.INTEGER, !1, i.getBytes())])])
         } else {
            var y = new Error("Cannot encrypt private key. Unknown encryption algorithm.");
            throw y.algorithm = a.algorithm, y
         }
         var F = b.create(b.Class.UNIVERSAL, b.Type.SEQUENCE, !0, [o, b.create(b.Class.UNIVERSAL, b.Type.OCTETSTRING, !1, u)]);
         return F
      };
      Z.decryptPrivateKeyInfo = function(e, t) {
         var a = null,
            r = {},
            n = [];
         if (!b.validate(e, Fd, r, n)) {
            var i = new Error("Cannot read encrypted private key. ASN.1 object is not a supported EncryptedPrivateKeyInfo.");
            throw i.errors = n, i
         }
         var s = b.derToOid(r.encryptionOid),
            o = Z.pbe.getCipher(s, r.encryptionParams, t),
            u = V.util.createBuffer(r.encryptedData);
         return o.update(u), o.finish() && (a = b.fromDer(o.output)), a
      };
      Z.encryptedPrivateKeyToPem = function(e, t) {
         var a = {
            type: "ENCRYPTED PRIVATE KEY",
            body: b.toDer(e).getBytes()
         };
         return V.pem.encode(a, {
            maxline: t
         })
      };
      Z.encryptedPrivateKeyFromPem = function(e) {
         var t = V.pem.decode(e)[0];
         if (t.type !== "ENCRYPTED PRIVATE KEY") {
            var a = new Error('Could not convert encrypted private key from PEM; PEM header type is "ENCRYPTED PRIVATE KEY".');
            throw a.headerType = t.type, a
         }
         if (t.procType && t.procType.type === "ENCRYPTED") throw new Error("Could not convert encrypted private key from PEM; PEM is encrypted.");
         return b.fromDer(t.body)
      };
      Z.encryptRsaPrivateKey = function(e, t, a) {
         if (a = a || {}, !a.legacy) {
            var r = Z.wrapRsaPrivateKey(Z.privateKeyToAsn1(e));
            return r = Z.encryptPrivateKeyInfo(r, t, a), Z.encryptedPrivateKeyToPem(r)
         }
         var n, i, s, o;
         switch (a.algorithm) {
            case "aes128":
               n = "AES-128-CBC", s = 16, i = V.random.getBytesSync(16), o = V.aes.createEncryptionCipher;
               break;
            case "aes192":
               n = "AES-192-CBC", s = 24, i = V.random.getBytesSync(16), o = V.aes.createEncryptionCipher;
               break;
            case "aes256":
               n = "AES-256-CBC", s = 32, i = V.random.getBytesSync(16), o = V.aes.createEncryptionCipher;
               break;
            case "3des":
               n = "DES-EDE3-CBC", s = 24, i = V.random.getBytesSync(8), o = V.des.createEncryptionCipher;
               break;
            case "des":
               n = "DES-CBC", s = 8, i = V.random.getBytesSync(8), o = V.des.createEncryptionCipher;
               break;
            default:
               var u = new Error('Could not encrypt RSA private key; unsupported encryption algorithm "' + a.algorithm + '".');
               throw u.algorithm = a.algorithm, u
         }
         var l = V.pbe.opensslDeriveBytes(t, i.substr(0, 8), s),
            c = o(l);
         c.start(i), c.update(b.toDer(Z.privateKeyToAsn1(e))), c.finish();
         var f = {
            type: "RSA PRIVATE KEY",
            procType: {
               version: "4",
               type: "ENCRYPTED"
            },
            dekInfo: {
               algorithm: n,
               parameters: V.util.bytesToHex(i).toUpperCase()
            },
            body: c.output.getBytes()
         };
         return V.pem.encode(f)
      };
      Z.decryptRsaPrivateKey = function(e, t) {
         var a = null,
            r = V.pem.decode(e)[0];
         if (r.type !== "ENCRYPTED PRIVATE KEY" && r.type !== "PRIVATE KEY" && r.type !== "RSA PRIVATE KEY") {
            var n = new Error('Could not convert private key from PEM; PEM header type is not "ENCRYPTED PRIVATE KEY", "PRIVATE KEY", or "RSA PRIVATE KEY".');
            throw n.headerType = n, n
         }
         if (r.procType && r.procType.type === "ENCRYPTED") {
            var i, s;
            switch (r.dekInfo.algorithm) {
               case "DES-CBC":
                  i = 8, s = V.des.createDecryptionCipher;
                  break;
               case "DES-EDE3-CBC":
                  i = 24, s = V.des.createDecryptionCipher;
                  break;
               case "AES-128-CBC":
                  i = 16, s = V.aes.createDecryptionCipher;
                  break;
               case "AES-192-CBC":
                  i = 24, s = V.aes.createDecryptionCipher;
                  break;
               case "AES-256-CBC":
                  i = 32, s = V.aes.createDecryptionCipher;
                  break;
               case "RC2-40-CBC":
                  i = 5, s = function(f) {
                     return V.rc2.createDecryptionCipher(f, 40)
                  };
                  break;
               case "RC2-64-CBC":
                  i = 8, s = function(f) {
                     return V.rc2.createDecryptionCipher(f, 64)
                  };
                  break;
               case "RC2-128-CBC":
                  i = 16, s = function(f) {
                     return V.rc2.createDecryptionCipher(f, 128)
                  };
                  break;
               default:
                  var n = new Error('Could not decrypt private key; unsupported encryption algorithm "' + r.dekInfo.algorithm + '".');
                  throw n.algorithm = r.dekInfo.algorithm, n
            }
            var o = V.util.hexToBytes(r.dekInfo.parameters),
               u = V.pbe.opensslDeriveBytes(t, o.substr(0, 8), i),
               l = s(u);
            if (l.start(o), l.update(V.util.createBuffer(r.body)), l.finish()) a = l.output.getBytes();
            else return a
         } else a = r.body;
         return r.type === "ENCRYPTED PRIVATE KEY" ? a = Z.decryptPrivateKeyInfo(b.fromDer(a), t) : a = b.fromDer(a), a !== null && (a = Z.privateKeyFromAsn1(a)), a
      };
      Z.pbe.generatePkcs12Key = function(e, t, a, r, n, i) {
         var s, o;
         if (typeof i > "u" || i === null) {
            if (!("sha1" in V.md)) throw new Error('"sha1" hash algorithm unavailable.');
            i = V.md.sha1.create()
         }
         var u = i.digestLength,
            l = i.blockLength,
            c = new V.util.ByteBuffer,
            f = new V.util.ByteBuffer;
         if (e != null) {
            for (o = 0; o < e.length; o++) f.putInt16(e.charCodeAt(o));
            f.putInt16(0)
         }
         var y = f.length(),
            g = t.length(),
            m = new V.util.ByteBuffer;
         m.fillWithByte(a, l);
         var x = l * Math.ceil(g / l),
            T = new V.util.ByteBuffer;
         for (o = 0; o < x; o++) T.putByte(t.at(o % g));
         var I = l * Math.ceil(y / l),
            A = new V.util.ByteBuffer;
         for (o = 0; o < I; o++) A.putByte(f.at(o % y));
         var B = T;
         B.putBuffer(A);
         for (var F = Math.ceil(n / u), R = 1; R <= F; R++) {
            var D = new V.util.ByteBuffer;
            D.putBytes(m.bytes()), D.putBytes(B.bytes());
            for (var G = 0; G < r; G++) i.start(), i.update(D.getBytes()), D = i.digest();
            var z = new V.util.ByteBuffer;
            for (o = 0; o < l; o++) z.putByte(D.at(o % u));
            var oe = Math.ceil(g / l) + Math.ceil(y / l),
               ce = new V.util.ByteBuffer;
            for (s = 0; s < oe; s++) {
               var pe = new V.util.ByteBuffer(B.getBytes(l)),
                  ge = 511;
               for (o = z.length() - 1; o >= 0; o--) ge = ge >> 8, ge += z.at(o) + pe.at(o), pe.setAt(o, ge & 255);
               ce.putBuffer(pe)
            }
            B = ce, c.putBuffer(D)
         }
         return c.truncate(c.length() - n), c
      };
      Z.pbe.getCipher = function(e, t, a) {
         switch (e) {
            case Z.oids.pkcs5PBES2:
               return Z.pbe.getCipherForPBES2(e, t, a);
            case Z.oids["pbeWithSHAAnd3-KeyTripleDES-CBC"]:
            case Z.oids["pbewithSHAAnd40BitRC2-CBC"]:
               return Z.pbe.getCipherForPKCS12PBE(e, t, a);
            default:
               var r = new Error("Cannot read encrypted PBE data block. Unsupported OID.");
               throw r.oid = e, r.supportedOids = ["pkcs5PBES2", "pbeWithSHAAnd3-KeyTripleDES-CBC", "pbewithSHAAnd40BitRC2-CBC"], r
         }
      };
      Z.pbe.getCipherForPBES2 = function(e, t, a) {
         var r = {},
            n = [];
         if (!b.validate(t, Pd, r, n)) {
            var i = new Error("Cannot read password-based-encryption algorithm parameters. ASN.1 object is not a supported EncryptedPrivateKeyInfo.");
            throw i.errors = n, i
         }
         if (e = b.derToOid(r.kdfOid), e !== Z.oids.pkcs5PBKDF2) {
            var i = new Error("Cannot read encrypted private key. Unsupported key derivation function OID.");
            throw i.oid = e, i.supportedOids = ["pkcs5PBKDF2"], i
         }
         if (e = b.derToOid(r.encOid), e !== Z.oids["aes128-CBC"] && e !== Z.oids["aes192-CBC"] && e !== Z.oids["aes256-CBC"] && e !== Z.oids["des-EDE3-CBC"] && e !== Z.oids.desCBC) {
            var i = new Error("Cannot read encrypted private key. Unsupported encryption scheme OID.");
            throw i.oid = e, i.supportedOids = ["aes128-CBC", "aes192-CBC", "aes256-CBC", "des-EDE3-CBC", "desCBC"], i
         }
         var s = r.kdfSalt,
            o = V.util.createBuffer(r.kdfIterationCount);
         o = o.getInt(o.length() << 3);
         var u, l;
         switch (Z.oids[e]) {
            case "aes128-CBC":
               u = 16, l = V.aes.createDecryptionCipher;
               break;
            case "aes192-CBC":
               u = 24, l = V.aes.createDecryptionCipher;
               break;
            case "aes256-CBC":
               u = 32, l = V.aes.createDecryptionCipher;
               break;
            case "des-EDE3-CBC":
               u = 24, l = V.des.createDecryptionCipher;
               break;
            case "desCBC":
               u = 8, l = V.des.createDecryptionCipher;
               break
         }
         var c = Cl(r.prfOid),
            f = V.pkcs5.pbkdf2(a, s, o, u, c),
            y = r.encIv,
            g = l(f);
         return g.start(y), g
      };
      Z.pbe.getCipherForPKCS12PBE = function(e, t, a) {
         var r = {},
            n = [];
         if (!b.validate(t, Vd, r, n)) {
            var i = new Error("Cannot read password-based-encryption algorithm parameters. ASN.1 object is not a supported EncryptedPrivateKeyInfo.");
            throw i.errors = n, i
         }
         var s = V.util.createBuffer(r.salt),
            o = V.util.createBuffer(r.iterations);
         o = o.getInt(o.length() << 3);
         var u, l, c;
         switch (e) {
            case Z.oids["pbeWithSHAAnd3-KeyTripleDES-CBC"]:
               u = 24, l = 8, c = V.des.startDecrypting;
               break;
            case Z.oids["pbewithSHAAnd40BitRC2-CBC"]:
               u = 5, l = 8, c = function(x, T) {
                  var I = V.rc2.createDecryptionCipher(x, 40);
                  return I.start(T, null), I
               };
               break;
            default:
               var i = new Error("Cannot read PKCS #12 PBE data block. Unsupported OID.");
               throw i.oid = e, i
         }
         var f = Cl(r.prfOid),
            y = Z.pbe.generatePkcs12Key(a, s, 1, o, u, f);
         f.start();
         var g = Z.pbe.generatePkcs12Key(a, s, 2, o, l, f);
         return c(y, g)
      };
      Z.pbe.opensslDeriveBytes = function(e, t, a, r) {
         if (typeof r > "u" || r === null) {
            if (!("md5" in V.md)) throw new Error('"md5" hash algorithm unavailable.');
            r = V.md.md5.create()
         }
         t === null && (t = "");
         for (var n = [El(r, e + t)], i = 16, s = 1; i < a; ++s, i += 16) n.push(El(r, n[s - 1] + e + t));
         return n.join("").substr(0, a)
      };

      function El(e, t) {
         return e.start().update(t).digest().getBytes()
      }

      function Cl(e) {
         var t;
         if (!e) t = "hmacWithSHA1";
         else if (t = Z.oids[b.derToOid(e)], !t) {
            var a = new Error("Unsupported PRF OID.");
            throw a.oid = e, a.supported = ["hmacWithSHA1", "hmacWithSHA224", "hmacWithSHA256", "hmacWithSHA384", "hmacWithSHA512"], a
         }
         return xl(t)
      }

      function xl(e) {
         var t = V.md;
         switch (e) {
            case "hmacWithSHA224":
               t = V.md.sha512;
            case "hmacWithSHA1":
            case "hmacWithSHA256":
            case "hmacWithSHA384":
            case "hmacWithSHA512":
               e = e.substr(8).toLowerCase();
               break;
            default:
               var a = new Error("Unsupported PRF algorithm.");
               throw a.algorithm = e, a.supported = ["hmacWithSHA1", "hmacWithSHA224", "hmacWithSHA256", "hmacWithSHA384", "hmacWithSHA512"], a
         }
         if (!t || !(e in t)) throw new Error("Unknown hash algorithm: " + e);
         return t[e].create()
      }

      function Md(e, t, a, r) {
         var n = b.create(b.Class.UNIVERSAL, b.Type.SEQUENCE, !0, [b.create(b.Class.UNIVERSAL, b.Type.OCTETSTRING, !1, e), b.create(b.Class.UNIVERSAL, b.Type.INTEGER, !1, t.getBytes())]);
         return r !== "hmacWithSHA1" && n.value.push(b.create(b.Class.UNIVERSAL, b.Type.INTEGER, !1, V.util.hexToBytes(a.toString(16))), b.create(b.Class.UNIVERSAL, b.Type.SEQUENCE, !0, [b.create(b.Class.UNIVERSAL, b.Type.OID, !1, b.oidToDer(Z.oids[r]).getBytes()), b.create(b.Class.UNIVERSAL, b.Type.NULL, !1, "")])), n
      }
   });
   var Ss = Y((Dg, bl) => {
      "use strict";
      var na = $();
      wt();
      ae();
      var P = na.asn1,
         ia = bl.exports = na.pkcs7asn1 = na.pkcs7asn1 || {};
      na.pkcs7 = na.pkcs7 || {};
      na.pkcs7.asn1 = ia;
      var Sl = {
         name: "ContentInfo",
         tagClass: P.Class.UNIVERSAL,
         type: P.Type.SEQUENCE,
         constructed: !0,
         value: [{
            name: "ContentInfo.ContentType",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.OID,
            constructed: !1,
            capture: "contentType"
         }, {
            name: "ContentInfo.content",
            tagClass: P.Class.CONTEXT_SPECIFIC,
            type: 0,
            constructed: !0,
            optional: !0,
            captureAsn1: "content"
         }]
      };
      ia.contentInfoValidator = Sl;
      var Il = {
         name: "EncryptedContentInfo",
         tagClass: P.Class.UNIVERSAL,
         type: P.Type.SEQUENCE,
         constructed: !0,
         value: [{
            name: "EncryptedContentInfo.contentType",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.OID,
            constructed: !1,
            capture: "contentType"
         }, {
            name: "EncryptedContentInfo.contentEncryptionAlgorithm",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "EncryptedContentInfo.contentEncryptionAlgorithm.algorithm",
               tagClass: P.Class.UNIVERSAL,
               type: P.Type.OID,
               constructed: !1,
               capture: "encAlgorithm"
            }, {
               name: "EncryptedContentInfo.contentEncryptionAlgorithm.parameter",
               tagClass: P.Class.UNIVERSAL,
               captureAsn1: "encParameter"
            }]
         }, {
            name: "EncryptedContentInfo.encryptedContent",
            tagClass: P.Class.CONTEXT_SPECIFIC,
            type: 0,
            capture: "encryptedContent",
            captureAsn1: "encryptedContentAsn1"
         }]
      };
      ia.envelopedDataValidator = {
         name: "EnvelopedData",
         tagClass: P.Class.UNIVERSAL,
         type: P.Type.SEQUENCE,
         constructed: !0,
         value: [{
            name: "EnvelopedData.Version",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.INTEGER,
            constructed: !1,
            capture: "version"
         }, {
            name: "EnvelopedData.RecipientInfos",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.SET,
            constructed: !0,
            captureAsn1: "recipientInfos"
         }].concat(Il)
      };
      ia.encryptedDataValidator = {
         name: "EncryptedData",
         tagClass: P.Class.UNIVERSAL,
         type: P.Type.SEQUENCE,
         constructed: !0,
         value: [{
            name: "EncryptedData.Version",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.INTEGER,
            constructed: !1,
            capture: "version"
         }].concat(Il)
      };
      var Kd = {
         name: "SignerInfo",
         tagClass: P.Class.UNIVERSAL,
         type: P.Type.SEQUENCE,
         constructed: !0,
         value: [{
            name: "SignerInfo.version",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.INTEGER,
            constructed: !1
         }, {
            name: "SignerInfo.issuerAndSerialNumber",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "SignerInfo.issuerAndSerialNumber.issuer",
               tagClass: P.Class.UNIVERSAL,
               type: P.Type.SEQUENCE,
               constructed: !0,
               captureAsn1: "issuer"
            }, {
               name: "SignerInfo.issuerAndSerialNumber.serialNumber",
               tagClass: P.Class.UNIVERSAL,
               type: P.Type.INTEGER,
               constructed: !1,
               capture: "serial"
            }]
         }, {
            name: "SignerInfo.digestAlgorithm",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "SignerInfo.digestAlgorithm.algorithm",
               tagClass: P.Class.UNIVERSAL,
               type: P.Type.OID,
               constructed: !1,
               capture: "digestAlgorithm"
            }, {
               name: "SignerInfo.digestAlgorithm.parameter",
               tagClass: P.Class.UNIVERSAL,
               constructed: !1,
               captureAsn1: "digestParameter",
               optional: !0
            }]
         }, {
            name: "SignerInfo.authenticatedAttributes",
            tagClass: P.Class.CONTEXT_SPECIFIC,
            type: 0,
            constructed: !0,
            optional: !0,
            capture: "authenticatedAttributes"
         }, {
            name: "SignerInfo.digestEncryptionAlgorithm",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.SEQUENCE,
            constructed: !0,
            capture: "signatureAlgorithm"
         }, {
            name: "SignerInfo.encryptedDigest",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.OCTETSTRING,
            constructed: !1,
            capture: "signature"
         }, {
            name: "SignerInfo.unauthenticatedAttributes",
            tagClass: P.Class.CONTEXT_SPECIFIC,
            type: 1,
            constructed: !0,
            optional: !0,
            capture: "unauthenticatedAttributes"
         }]
      };
      ia.signedDataValidator = {
         name: "SignedData",
         tagClass: P.Class.UNIVERSAL,
         type: P.Type.SEQUENCE,
         constructed: !0,
         value: [{
            name: "SignedData.Version",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.INTEGER,
            constructed: !1,
            capture: "version"
         }, {
            name: "SignedData.DigestAlgorithms",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.SET,
            constructed: !0,
            captureAsn1: "digestAlgorithms"
         }, Sl, {
            name: "SignedData.Certificates",
            tagClass: P.Class.CONTEXT_SPECIFIC,
            type: 0,
            optional: !0,
            captureAsn1: "certificates"
         }, {
            name: "SignedData.CertificateRevocationLists",
            tagClass: P.Class.CONTEXT_SPECIFIC,
            type: 1,
            optional: !0,
            captureAsn1: "crls"
         }, {
            name: "SignedData.SignerInfos",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.SET,
            capture: "signerInfos",
            optional: !0,
            value: [Kd]
         }]
      };
      ia.recipientInfoValidator = {
         name: "RecipientInfo",
         tagClass: P.Class.UNIVERSAL,
         type: P.Type.SEQUENCE,
         constructed: !0,
         value: [{
            name: "RecipientInfo.version",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.INTEGER,
            constructed: !1,
            capture: "version"
         }, {
            name: "RecipientInfo.issuerAndSerial",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "RecipientInfo.issuerAndSerial.issuer",
               tagClass: P.Class.UNIVERSAL,
               type: P.Type.SEQUENCE,
               constructed: !0,
               captureAsn1: "issuer"
            }, {
               name: "RecipientInfo.issuerAndSerial.serialNumber",
               tagClass: P.Class.UNIVERSAL,
               type: P.Type.INTEGER,
               constructed: !1,
               capture: "serial"
            }]
         }, {
            name: "RecipientInfo.keyEncryptionAlgorithm",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "RecipientInfo.keyEncryptionAlgorithm.algorithm",
               tagClass: P.Class.UNIVERSAL,
               type: P.Type.OID,
               constructed: !1,
               capture: "encAlgorithm"
            }, {
               name: "RecipientInfo.keyEncryptionAlgorithm.parameter",
               tagClass: P.Class.UNIVERSAL,
               constructed: !1,
               captureAsn1: "encParameter",
               optional: !0
            }]
         }, {
            name: "RecipientInfo.encryptedKey",
            tagClass: P.Class.UNIVERSAL,
            type: P.Type.OCTETSTRING,
            constructed: !1,
            capture: "encKey"
         }]
      }
   });
   var Is = Y((Rg, Al) => {
      "use strict";
      var Br = $();
      ae();
      Br.mgf = Br.mgf || {};
      var qd = Al.exports = Br.mgf.mgf1 = Br.mgf1 = Br.mgf1 || {};
      qd.create = function(e) {
         var t = {
            generate: function(a, r) {
               for (var n = new Br.util.ByteBuffer, i = Math.ceil(r / e.digestLength), s = 0; s < i; s++) {
                  var o = new Br.util.ByteBuffer;
                  o.putInt32(s), e.start(), e.update(a + o.getBytes()), n.putBuffer(e.digest())
               }
               return n.truncate(n.length() - r), n.getBytes()
            }
         };
         return t
      }
   });
   var wl = Y((Lg, Bl) => {
      "use strict";
      var jn = $();
      Is();
      Bl.exports = jn.mgf = jn.mgf || {};
      jn.mgf.mgf1 = jn.mgf1
   });
   var Xn = Y((kg, Nl) => {
      "use strict";
      var wr = $();
      mt();
      ae();
      var Hd = Nl.exports = wr.pss = wr.pss || {};
      Hd.create = function(e) {
         arguments.length === 3 && (e = {
            md: arguments[0],
            mgf: arguments[1],
            saltLength: arguments[2]
         });
         var t = e.md,
            a = e.mgf,
            r = t.digestLength,
            n = e.salt || null;
         typeof n == "string" && (n = wr.util.createBuffer(n));
         var i;
         if ("saltLength" in e) i = e.saltLength;
         else if (n !== null) i = n.length();
         else throw new Error("Salt length not specified or specific salt not given.");
         if (n !== null && n.length() !== i) throw new Error("Given salt length does not match length of given salt.");
         var s = e.prng || wr.random,
            o = {};
         return o.encode = function(u, l) {
            var c, f = l - 1,
               y = Math.ceil(f / 8),
               g = u.digest().getBytes();
            if (y < r + i + 2) throw new Error("Message is too long to encrypt.");
            var m;
            n === null ? m = s.getBytesSync(i) : m = n.bytes();
            var x = new wr.util.ByteBuffer;
            x.fillWithByte(0, 8), x.putBytes(g), x.putBytes(m), t.start(), t.update(x.getBytes());
            var T = t.digest().getBytes(),
               I = new wr.util.ByteBuffer;
            I.fillWithByte(0, y - i - r - 2), I.putByte(1), I.putBytes(m);
            var A = I.getBytes(),
               B = y - r - 1,
               F = a.generate(T, B),
               R = "";
            for (c = 0; c < B; c++) R += String.fromCharCode(A.charCodeAt(c) ^ F.charCodeAt(c));
            var D = 65280 >> 8 * y - f & 255;
            return R = String.fromCharCode(R.charCodeAt(0) & ~D) + R.substr(1), R + T + String.fromCharCode(188)
         }, o.verify = function(u, l, c) {
            var f, y = c - 1,
               g = Math.ceil(y / 8);
            if (l = l.substr(-g), g < r + i + 2) throw new Error("Inconsistent parameters to PSS signature verification.");
            if (l.charCodeAt(g - 1) !== 188) throw new Error("Encoded message does not end in 0xBC.");
            var m = g - r - 1,
               x = l.substr(0, m),
               T = l.substr(m, r),
               I = 65280 >> 8 * g - y & 255;
            if (x.charCodeAt(0) & I) throw new Error("Bits beyond keysize not zero as expected.");
            var A = a.generate(T, m),
               B = "";
            for (f = 0; f < m; f++) B += String.fromCharCode(x.charCodeAt(f) ^ A.charCodeAt(f));
            B = String.fromCharCode(B.charCodeAt(0) & ~I) + B.substr(1);
            var F = g - r - i - 2;
            for (f = 0; f < F; f++)
               if (B.charCodeAt(f) !== 0) throw new Error("Leftmost octets not zero as expected");
            if (B.charCodeAt(F) !== 1) throw new Error("Inconsistent PSS signature, 0x01 marker not found");
            var R = B.substr(-i),
               D = new wr.util.ByteBuffer;
            D.fillWithByte(0, 8), D.putBytes(u), D.putBytes(R), t.start(), t.update(D.getBytes());
            var G = t.digest().getBytes();
            return T === G
         }, o
      }
   });
   var ti = Y((Og, kl) => {
      "use strict";
      var q = $();
      sr();
      wt();
      Ja();
      Rt();
      wl();
      or();
      Sr();
      Xn();
      rn();
      ae();
      var h = q.asn1,
         L = kl.exports = q.pki = q.pki || {},
         re = L.oids,
         Se = {};
      Se.CN = re.commonName;
      Se.commonName = "CN";
      Se.C = re.countryName;
      Se.countryName = "C";
      Se.L = re.localityName;
      Se.localityName = "L";
      Se.ST = re.stateOrProvinceName;
      Se.stateOrProvinceName = "ST";
      Se.O = re.organizationName;
      Se.organizationName = "O";
      Se.OU = re.organizationalUnitName;
      Se.organizationalUnitName = "OU";
      Se.E = re.emailAddress;
      Se.emailAddress = "E";
      var Dl = q.pki.rsa.publicKeyValidator,
         Gd = {
            name: "Certificate",
            tagClass: h.Class.UNIVERSAL,
            type: h.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "Certificate.TBSCertificate",
               tagClass: h.Class.UNIVERSAL,
               type: h.Type.SEQUENCE,
               constructed: !0,
               captureAsn1: "tbsCertificate",
               value: [{
                  name: "Certificate.TBSCertificate.version",
                  tagClass: h.Class.CONTEXT_SPECIFIC,
                  type: 0,
                  constructed: !0,
                  optional: !0,
                  value: [{
                     name: "Certificate.TBSCertificate.version.integer",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.INTEGER,
                     constructed: !1,
                     capture: "certVersion"
                  }]
               }, {
                  name: "Certificate.TBSCertificate.serialNumber",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Type.INTEGER,
                  constructed: !1,
                  capture: "certSerialNumber"
               }, {
                  name: "Certificate.TBSCertificate.signature",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Type.SEQUENCE,
                  constructed: !0,
                  value: [{
                     name: "Certificate.TBSCertificate.signature.algorithm",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.OID,
                     constructed: !1,
                     capture: "certinfoSignatureOid"
                  }, {
                     name: "Certificate.TBSCertificate.signature.parameters",
                     tagClass: h.Class.UNIVERSAL,
                     optional: !0,
                     captureAsn1: "certinfoSignatureParams"
                  }]
               }, {
                  name: "Certificate.TBSCertificate.issuer",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Type.SEQUENCE,
                  constructed: !0,
                  captureAsn1: "certIssuer"
               }, {
                  name: "Certificate.TBSCertificate.validity",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Type.SEQUENCE,
                  constructed: !0,
                  value: [{
                     name: "Certificate.TBSCertificate.validity.notBefore (utc)",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.UTCTIME,
                     constructed: !1,
                     optional: !0,
                     capture: "certValidity1UTCTime"
                  }, {
                     name: "Certificate.TBSCertificate.validity.notBefore (generalized)",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.GENERALIZEDTIME,
                     constructed: !1,
                     optional: !0,
                     capture: "certValidity2GeneralizedTime"
                  }, {
                     name: "Certificate.TBSCertificate.validity.notAfter (utc)",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.UTCTIME,
                     constructed: !1,
                     optional: !0,
                     capture: "certValidity3UTCTime"
                  }, {
                     name: "Certificate.TBSCertificate.validity.notAfter (generalized)",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.GENERALIZEDTIME,
                     constructed: !1,
                     optional: !0,
                     capture: "certValidity4GeneralizedTime"
                  }]
               }, {
                  name: "Certificate.TBSCertificate.subject",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Type.SEQUENCE,
                  constructed: !0,
                  captureAsn1: "certSubject"
               }, Dl, {
                  name: "Certificate.TBSCertificate.issuerUniqueID",
                  tagClass: h.Class.CONTEXT_SPECIFIC,
                  type: 1,
                  constructed: !0,
                  optional: !0,
                  value: [{
                     name: "Certificate.TBSCertificate.issuerUniqueID.id",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.BITSTRING,
                     constructed: !1,
                     captureBitStringValue: "certIssuerUniqueId"
                  }]
               }, {
                  name: "Certificate.TBSCertificate.subjectUniqueID",
                  tagClass: h.Class.CONTEXT_SPECIFIC,
                  type: 2,
                  constructed: !0,
                  optional: !0,
                  value: [{
                     name: "Certificate.TBSCertificate.subjectUniqueID.id",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.BITSTRING,
                     constructed: !1,
                     captureBitStringValue: "certSubjectUniqueId"
                  }]
               }, {
                  name: "Certificate.TBSCertificate.extensions",
                  tagClass: h.Class.CONTEXT_SPECIFIC,
                  type: 3,
                  constructed: !0,
                  captureAsn1: "certExtensions",
                  optional: !0
               }]
            }, {
               name: "Certificate.signatureAlgorithm",
               tagClass: h.Class.UNIVERSAL,
               type: h.Type.SEQUENCE,
               constructed: !0,
               value: [{
                  name: "Certificate.signatureAlgorithm.algorithm",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Type.OID,
                  constructed: !1,
                  capture: "certSignatureOid"
               }, {
                  name: "Certificate.TBSCertificate.signature.parameters",
                  tagClass: h.Class.UNIVERSAL,
                  optional: !0,
                  captureAsn1: "certSignatureParams"
               }]
            }, {
               name: "Certificate.signatureValue",
               tagClass: h.Class.UNIVERSAL,
               type: h.Type.BITSTRING,
               constructed: !1,
               captureBitStringValue: "certSignature"
            }]
         },
         zd = {
            name: "rsapss",
            tagClass: h.Class.UNIVERSAL,
            type: h.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "rsapss.hashAlgorithm",
               tagClass: h.Class.CONTEXT_SPECIFIC,
               type: 0,
               constructed: !0,
               value: [{
                  name: "rsapss.hashAlgorithm.AlgorithmIdentifier",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Class.SEQUENCE,
                  constructed: !0,
                  optional: !0,
                  value: [{
                     name: "rsapss.hashAlgorithm.AlgorithmIdentifier.algorithm",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.OID,
                     constructed: !1,
                     capture: "hashOid"
                  }]
               }]
            }, {
               name: "rsapss.maskGenAlgorithm",
               tagClass: h.Class.CONTEXT_SPECIFIC,
               type: 1,
               constructed: !0,
               value: [{
                  name: "rsapss.maskGenAlgorithm.AlgorithmIdentifier",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Class.SEQUENCE,
                  constructed: !0,
                  optional: !0,
                  value: [{
                     name: "rsapss.maskGenAlgorithm.AlgorithmIdentifier.algorithm",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.OID,
                     constructed: !1,
                     capture: "maskGenOid"
                  }, {
                     name: "rsapss.maskGenAlgorithm.AlgorithmIdentifier.params",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.SEQUENCE,
                     constructed: !0,
                     value: [{
                        name: "rsapss.maskGenAlgorithm.AlgorithmIdentifier.params.algorithm",
                        tagClass: h.Class.UNIVERSAL,
                        type: h.Type.OID,
                        constructed: !1,
                        capture: "maskGenHashOid"
                     }]
                  }]
               }]
            }, {
               name: "rsapss.saltLength",
               tagClass: h.Class.CONTEXT_SPECIFIC,
               type: 2,
               optional: !0,
               value: [{
                  name: "rsapss.saltLength.saltLength",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Class.INTEGER,
                  constructed: !1,
                  capture: "saltLength"
               }]
            }, {
               name: "rsapss.trailerField",
               tagClass: h.Class.CONTEXT_SPECIFIC,
               type: 3,
               optional: !0,
               value: [{
                  name: "rsapss.trailer.trailer",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Class.INTEGER,
                  constructed: !1,
                  capture: "trailer"
               }]
            }]
         },
         Wd = {
            name: "CertificationRequestInfo",
            tagClass: h.Class.UNIVERSAL,
            type: h.Type.SEQUENCE,
            constructed: !0,
            captureAsn1: "certificationRequestInfo",
            value: [{
               name: "CertificationRequestInfo.integer",
               tagClass: h.Class.UNIVERSAL,
               type: h.Type.INTEGER,
               constructed: !1,
               capture: "certificationRequestInfoVersion"
            }, {
               name: "CertificationRequestInfo.subject",
               tagClass: h.Class.UNIVERSAL,
               type: h.Type.SEQUENCE,
               constructed: !0,
               captureAsn1: "certificationRequestInfoSubject"
            }, Dl, {
               name: "CertificationRequestInfo.attributes",
               tagClass: h.Class.CONTEXT_SPECIFIC,
               type: 0,
               constructed: !0,
               optional: !0,
               capture: "certificationRequestInfoAttributes",
               value: [{
                  name: "CertificationRequestInfo.attributes",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Type.SEQUENCE,
                  constructed: !0,
                  value: [{
                     name: "CertificationRequestInfo.attributes.type",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.OID,
                     constructed: !1
                  }, {
                     name: "CertificationRequestInfo.attributes.value",
                     tagClass: h.Class.UNIVERSAL,
                     type: h.Type.SET,
                     constructed: !0
                  }]
               }]
            }]
         },
         Yd = {
            name: "CertificationRequest",
            tagClass: h.Class.UNIVERSAL,
            type: h.Type.SEQUENCE,
            constructed: !0,
            captureAsn1: "csr",
            value: [Wd, {
               name: "CertificationRequest.signatureAlgorithm",
               tagClass: h.Class.UNIVERSAL,
               type: h.Type.SEQUENCE,
               constructed: !0,
               value: [{
                  name: "CertificationRequest.signatureAlgorithm.algorithm",
                  tagClass: h.Class.UNIVERSAL,
                  type: h.Type.OID,
                  constructed: !1,
                  capture: "csrSignatureOid"
               }, {
                  name: "CertificationRequest.signatureAlgorithm.parameters",
                  tagClass: h.Class.UNIVERSAL,
                  optional: !0,
                  captureAsn1: "csrSignatureParams"
               }]
            }, {
               name: "CertificationRequest.signature",
               tagClass: h.Class.UNIVERSAL,
               type: h.Type.BITSTRING,
               constructed: !1,
               captureBitStringValue: "csrSignature"
            }]
         };
      L.RDNAttributesAsArray = function(e, t) {
         for (var a = [], r, n, i, s = 0; s < e.value.length; ++s) {
            r = e.value[s];
            for (var o = 0; o < r.value.length; ++o) i = {}, n = r.value[o], i.type = h.derToOid(n.value[0].value), i.value = n.value[1].value, i.valueTagClass = n.value[1].type, i.type in re && (i.name = re[i.type], i.name in Se && (i.shortName = Se[i.name])), t && (t.update(i.type), t.update(i.value)), a.push(i)
         }
         return a
      };
      L.CRIAttributesAsArray = function(e) {
         for (var t = [], a = 0; a < e.length; ++a)
            for (var r = e[a], n = h.derToOid(r.value[0].value), i = r.value[1].value, s = 0; s < i.length; ++s) {
               var o = {};
               if (o.type = n, o.value = i[s].value, o.valueTagClass = i[s].type, o.type in re && (o.name = re[o.type], o.name in Se && (o.shortName = Se[o.name])), o.type === re.extensionRequest) {
                  o.extensions = [];
                  for (var u = 0; u < o.value.length; ++u) o.extensions.push(L.certificateExtensionFromAsn1(o.value[u]))
               }
               t.push(o)
            }
         return t
      };

      function cr(e, t) {
         typeof t == "string" && (t = {
            shortName: t
         });
         for (var a = null, r, n = 0; a === null && n < e.attributes.length; ++n) r = e.attributes[n], (t.type && t.type === r.type || t.name && t.name === r.name || t.shortName && t.shortName === r.shortName) && (a = r);
         return a
      }
      var Jn = function(e, t, a) {
            var r = {};
            if (e !== re["RSASSA-PSS"]) return r;
            a && (r = {
               hash: {
                  algorithmOid: re.sha1
               },
               mgf: {
                  algorithmOid: re.mgf1,
                  hash: {
                     algorithmOid: re.sha1
                  }
               },
               saltLength: 20
            });
            var n = {},
               i = [];
            if (!h.validate(t, zd, n, i)) {
               var s = new Error("Cannot read RSASSA-PSS parameter block.");
               throw s.errors = i, s
            }
            return n.hashOid !== void 0 && (r.hash = r.hash || {}, r.hash.algorithmOid = h.derToOid(n.hashOid)), n.maskGenOid !== void 0 && (r.mgf = r.mgf || {}, r.mgf.algorithmOid = h.derToOid(n.maskGenOid), r.mgf.hash = r.mgf.hash || {}, r.mgf.hash.algorithmOid = h.derToOid(n.maskGenHashOid)), n.saltLength !== void 0 && (r.saltLength = n.saltLength.charCodeAt(0)), r
         },
         ei = function(e) {
            switch (re[e.signatureOid]) {
               case "sha1WithRSAEncryption":
               case "sha1WithRSASignature":
                  return q.md.sha1.create();
               case "md5WithRSAEncryption":
                  return q.md.md5.create();
               case "sha256WithRSAEncryption":
                  return q.md.sha256.create();
               case "sha384WithRSAEncryption":
                  return q.md.sha384.create();
               case "sha512WithRSAEncryption":
                  return q.md.sha512.create();
               case "RSASSA-PSS":
                  return q.md.sha256.create();
               default:
                  var t = new Error("Could not compute " + e.type + " digest. Unknown signature OID.");
                  throw t.signatureOid = e.signatureOid, t
            }
         },
         Rl = function(e) {
            var t = e.certificate,
               a;
            switch (t.signatureOid) {
               case re.sha1WithRSAEncryption:
               case re.sha1WithRSASignature:
                  break;
               case re["RSASSA-PSS"]:
                  var r, n;
                  if (r = re[t.signatureParameters.mgf.hash.algorithmOid], r === void 0 || q.md[r] === void 0) {
                     var i = new Error("Unsupported MGF hash function.");
                     throw i.oid = t.signatureParameters.mgf.hash.algorithmOid, i.name = r, i
                  }
                  if (n = re[t.signatureParameters.mgf.algorithmOid], n === void 0 || q.mgf[n] === void 0) {
                     var i = new Error("Unsupported MGF function.");
                     throw i.oid = t.signatureParameters.mgf.algorithmOid, i.name = n, i
                  }
                  if (n = q.mgf[n].create(q.md[r].create()), r = re[t.signatureParameters.hash.algorithmOid], r === void 0 || q.md[r] === void 0) {
                     var i = new Error("Unsupported RSASSA-PSS hash function.");
                     throw i.oid = t.signatureParameters.hash.algorithmOid, i.name = r, i
                  }
                  a = q.pss.create(q.md[r].create(), n, t.signatureParameters.saltLength);
                  break
            }
            return t.publicKey.verify(e.md.digest().getBytes(), e.signature, a)
         };
      L.certificateFromPem = function(e, t, a) {
         var r = q.pem.decode(e)[0];
         if (r.type !== "CERTIFICATE" && r.type !== "X509 CERTIFICATE" && r.type !== "TRUSTED CERTIFICATE") {
            var n = new Error('Could not convert certificate from PEM; PEM header type is not "CERTIFICATE", "X509 CERTIFICATE", or "TRUSTED CERTIFICATE".');
            throw n.headerType = r.type, n
         }
         if (r.procType && r.procType.type === "ENCRYPTED") throw new Error("Could not convert certificate from PEM; PEM is encrypted.");
         var i = h.fromDer(r.body, a);
         return L.certificateFromAsn1(i, t)
      };
      L.certificateToPem = function(e, t) {
         var a = {
            type: "CERTIFICATE",
            body: h.toDer(L.certificateToAsn1(e)).getBytes()
         };
         return q.pem.encode(a, {
            maxline: t
         })
      };
      L.publicKeyFromPem = function(e) {
         var t = q.pem.decode(e)[0];
         if (t.type !== "PUBLIC KEY" && t.type !== "RSA PUBLIC KEY") {
            var a = new Error('Could not convert public key from PEM; PEM header type is not "PUBLIC KEY" or "RSA PUBLIC KEY".');
            throw a.headerType = t.type, a
         }
         if (t.procType && t.procType.type === "ENCRYPTED") throw new Error("Could not convert public key from PEM; PEM is encrypted.");
         var r = h.fromDer(t.body);
         return L.publicKeyFromAsn1(r)
      };
      L.publicKeyToPem = function(e, t) {
         var a = {
            type: "PUBLIC KEY",
            body: h.toDer(L.publicKeyToAsn1(e)).getBytes()
         };
         return q.pem.encode(a, {
            maxline: t
         })
      };
      L.publicKeyToRSAPublicKeyPem = function(e, t) {
         var a = {
            type: "RSA PUBLIC KEY",
            body: h.toDer(L.publicKeyToRSAPublicKey(e)).getBytes()
         };
         return q.pem.encode(a, {
            maxline: t
         })
      };
      L.getPublicKeyFingerprint = function(e, t) {
         t = t || {};
         var a = t.md || q.md.sha1.create(),
            r = t.type || "RSAPublicKey",
            n;
         switch (r) {
            case "RSAPublicKey":
               n = h.toDer(L.publicKeyToRSAPublicKey(e)).getBytes();
               break;
            case "SubjectPublicKeyInfo":
               n = h.toDer(L.publicKeyToAsn1(e)).getBytes();
               break;
            default:
               throw new Error('Unknown fingerprint type "' + t.type + '".')
         }
         a.start(), a.update(n);
         var i = a.digest();
         if (t.encoding === "hex") {
            var s = i.toHex();
            return t.delimiter ? s.match(/.{2}/g).join(t.delimiter) : s
         } else {
            if (t.encoding === "binary") return i.getBytes();
            if (t.encoding) throw new Error('Unknown encoding "' + t.encoding + '".')
         }
         return i
      };
      L.certificationRequestFromPem = function(e, t, a) {
         var r = q.pem.decode(e)[0];
         if (r.type !== "CERTIFICATE REQUEST") {
            var n = new Error('Could not convert certification request from PEM; PEM header type is not "CERTIFICATE REQUEST".');
            throw n.headerType = r.type, n
         }
         if (r.procType && r.procType.type === "ENCRYPTED") throw new Error("Could not convert certification request from PEM; PEM is encrypted.");
         var i = h.fromDer(r.body, a);
         return L.certificationRequestFromAsn1(i, t)
      };
      L.certificationRequestToPem = function(e, t) {
         var a = {
            type: "CERTIFICATE REQUEST",
            body: h.toDer(L.certificationRequestToAsn1(e)).getBytes()
         };
         return q.pem.encode(a, {
            maxline: t
         })
      };
      L.createCertificate = function() {
         var e = {};
         return e.version = 2, e.serialNumber = "00", e.signatureOid = null, e.signature = null, e.siginfo = {}, e.siginfo.algorithmOid = null, e.validity = {}, e.validity.notBefore = new Date, e.validity.notAfter = new Date, e.issuer = {}, e.issuer.getField = function(t) {
            return cr(e.issuer, t)
         }, e.issuer.addField = function(t) {
            Et([t]), e.issuer.attributes.push(t)
         }, e.issuer.attributes = [], e.issuer.hash = null, e.subject = {}, e.subject.getField = function(t) {
            return cr(e.subject, t)
         }, e.subject.addField = function(t) {
            Et([t]), e.subject.attributes.push(t)
         }, e.subject.attributes = [], e.subject.hash = null, e.extensions = [], e.publicKey = null, e.md = null, e.setSubject = function(t, a) {
            Et(t), e.subject.attributes = t, delete e.subject.uniqueId, a && (e.subject.uniqueId = a), e.subject.hash = null
         }, e.setIssuer = function(t, a) {
            Et(t), e.issuer.attributes = t, delete e.issuer.uniqueId, a && (e.issuer.uniqueId = a), e.issuer.hash = null
         }, e.setExtensions = function(t) {
            for (var a = 0; a < t.length; ++a) Ll(t[a], {
               cert: e
            });
            e.extensions = t
         }, e.getExtension = function(t) {
            typeof t == "string" && (t = {
               name: t
            });
            for (var a = null, r, n = 0; a === null && n < e.extensions.length; ++n) r = e.extensions[n], (t.id && r.id === t.id || t.name && r.name === t.name) && (a = r);
            return a
         }, e.sign = function(t, a) {
            e.md = a || q.md.sha1.create();
            var r = re[e.md.algorithm + "WithRSAEncryption"];
            if (!r) {
               var n = new Error("Could not compute certificate digest. Unknown message digest algorithm OID.");
               throw n.algorithm = e.md.algorithm, n
            }
            e.signatureOid = e.siginfo.algorithmOid = r, e.tbsCertificate = L.getTBSCertificate(e);
            var i = h.toDer(e.tbsCertificate);
            e.md.update(i.getBytes()), e.signature = t.sign(e.md)
         }, e.verify = function(t) {
            var a = !1;
            if (!e.issued(t)) {
               var r = t.issuer,
                  n = e.subject,
                  i = new Error("The parent certificate did not issue the given child certificate; the child certificate's issuer does not match the parent's subject.");
               throw i.expectedIssuer = n.attributes, i.actualIssuer = r.attributes, i
            }
            var s = t.md;
            if (s === null) {
               s = ei({
                  signatureOid: t.signatureOid,
                  type: "certificate"
               });
               var o = t.tbsCertificate || L.getTBSCertificate(t),
                  u = h.toDer(o);
               s.update(u.getBytes())
            }
            return s !== null && (a = Rl({
               certificate: e,
               md: s,
               signature: t.signature
            })), a
         }, e.isIssuer = function(t) {
            var a = !1,
               r = e.issuer,
               n = t.subject;
            if (r.hash && n.hash) a = r.hash === n.hash;
            else if (r.attributes.length === n.attributes.length) {
               a = !0;
               for (var i, s, o = 0; a && o < r.attributes.length; ++o) i = r.attributes[o], s = n.attributes[o], (i.type !== s.type || i.value !== s.value) && (a = !1)
            }
            return a
         }, e.issued = function(t) {
            return t.isIssuer(e)
         }, e.generateSubjectKeyIdentifier = function() {
            return L.getPublicKeyFingerprint(e.publicKey, {
               type: "RSAPublicKey"
            })
         }, e.verifySubjectKeyIdentifier = function() {
            for (var t = re.subjectKeyIdentifier, a = 0; a < e.extensions.length; ++a) {
               var r = e.extensions[a];
               if (r.id === t) {
                  var n = e.generateSubjectKeyIdentifier().getBytes();
                  return q.util.hexToBytes(r.subjectKeyIdentifier) === n
               }
            }
            return !1
         }, e
      };
      L.certificateFromAsn1 = function(e, t) {
         var a = {},
            r = [];
         if (!h.validate(e, Gd, a, r)) {
            var n = new Error("Cannot read X.509 certificate. ASN.1 object is not an X509v3 Certificate.");
            throw n.errors = r, n
         }
         var i = h.derToOid(a.publicKeyOid);
         if (i !== L.oids.rsaEncryption) throw new Error("Cannot read public key. OID is not RSA.");
         var s = L.createCertificate();
         s.version = a.certVersion ? a.certVersion.charCodeAt(0) : 0;
         var o = q.util.createBuffer(a.certSerialNumber);
         s.serialNumber = o.toHex(), s.signatureOid = q.asn1.derToOid(a.certSignatureOid), s.signatureParameters = Jn(s.signatureOid, a.certSignatureParams, !0), s.siginfo.algorithmOid = q.asn1.derToOid(a.certinfoSignatureOid), s.siginfo.parameters = Jn(s.siginfo.algorithmOid, a.certinfoSignatureParams, !1), s.signature = a.certSignature;
         var u = [];
         if (a.certValidity1UTCTime !== void 0 && u.push(h.utcTimeToDate(a.certValidity1UTCTime)), a.certValidity2GeneralizedTime !== void 0 && u.push(h.generalizedTimeToDate(a.certValidity2GeneralizedTime)), a.certValidity3UTCTime !== void 0 && u.push(h.utcTimeToDate(a.certValidity3UTCTime)), a.certValidity4GeneralizedTime !== void 0 && u.push(h.generalizedTimeToDate(a.certValidity4GeneralizedTime)), u.length > 2) throw new Error("Cannot read notBefore/notAfter validity times; more than two times were provided in the certificate.");
         if (u.length < 2) throw new Error("Cannot read notBefore/notAfter validity times; they were not provided as either UTCTime or GeneralizedTime.");
         if (s.validity.notBefore = u[0], s.validity.notAfter = u[1], s.tbsCertificate = a.tbsCertificate, t) {
            s.md = ei({
               signatureOid: s.signatureOid,
               type: "certificate"
            });
            var l = h.toDer(s.tbsCertificate);
            s.md.update(l.getBytes())
         }
         var c = q.md.sha1.create(),
            f = h.toDer(a.certIssuer);
         c.update(f.getBytes()), s.issuer.getField = function(m) {
            return cr(s.issuer, m)
         }, s.issuer.addField = function(m) {
            Et([m]), s.issuer.attributes.push(m)
         }, s.issuer.attributes = L.RDNAttributesAsArray(a.certIssuer), a.certIssuerUniqueId && (s.issuer.uniqueId = a.certIssuerUniqueId), s.issuer.hash = c.digest().toHex();
         var y = q.md.sha1.create(),
            g = h.toDer(a.certSubject);
         return y.update(g.getBytes()), s.subject.getField = function(m) {
            return cr(s.subject, m)
         }, s.subject.addField = function(m) {
            Et([m]), s.subject.attributes.push(m)
         }, s.subject.attributes = L.RDNAttributesAsArray(a.certSubject), a.certSubjectUniqueId && (s.subject.uniqueId = a.certSubjectUniqueId), s.subject.hash = y.digest().toHex(), a.certExtensions ? s.extensions = L.certificateExtensionsFromAsn1(a.certExtensions) : s.extensions = [], s.publicKey = L.publicKeyFromAsn1(a.subjectPublicKeyInfo), s
      };
      L.certificateExtensionsFromAsn1 = function(e) {
         for (var t = [], a = 0; a < e.value.length; ++a)
            for (var r = e.value[a], n = 0; n < r.value.length; ++n) t.push(L.certificateExtensionFromAsn1(r.value[n]));
         return t
      };
      L.certificateExtensionFromAsn1 = function(e) {
         var t = {};
         if (t.id = h.derToOid(e.value[0].value), t.critical = !1, e.value[1].type === h.Type.BOOLEAN ? (t.critical = e.value[1].value.charCodeAt(0) !== 0, t.value = e.value[2].value) : t.value = e.value[1].value, t.id in re) {
            if (t.name = re[t.id], t.name === "keyUsage") {
               var a = h.fromDer(t.value),
                  r = 0,
                  n = 0;
               a.value.length > 1 && (r = a.value.charCodeAt(1), n = a.value.length > 2 ? a.value.charCodeAt(2) : 0), t.digitalSignature = (r & 128) === 128, t.nonRepudiation = (r & 64) === 64, t.keyEncipherment = (r & 32) === 32, t.dataEncipherment = (r & 16) === 16, t.keyAgreement = (r & 8) === 8, t.keyCertSign = (r & 4) === 4, t.cRLSign = (r & 2) === 2, t.encipherOnly = (r & 1) === 1, t.decipherOnly = (n & 128) === 128
            } else if (t.name === "basicConstraints") {
               var a = h.fromDer(t.value);
               a.value.length > 0 && a.value[0].type === h.Type.BOOLEAN ? t.cA = a.value[0].value.charCodeAt(0) !== 0 : t.cA = !1;
               var i = null;
               a.value.length > 0 && a.value[0].type === h.Type.INTEGER ? i = a.value[0].value : a.value.length > 1 && (i = a.value[1].value), i !== null && (t.pathLenConstraint = h.derToInteger(i))
            } else if (t.name === "extKeyUsage")
               for (var a = h.fromDer(t.value), s = 0; s < a.value.length; ++s) {
                  var o = h.derToOid(a.value[s].value);
                  o in re ? t[re[o]] = !0 : t[o] = !0
               } else if (t.name === "nsCertType") {
                  var a = h.fromDer(t.value),
                     r = 0;
                  a.value.length > 1 && (r = a.value.charCodeAt(1)), t.client = (r & 128) === 128, t.server = (r & 64) === 64, t.email = (r & 32) === 32, t.objsign = (r & 16) === 16, t.reserved = (r & 8) === 8, t.sslCA = (r & 4) === 4, t.emailCA = (r & 2) === 2, t.objCA = (r & 1) === 1
               } else if (t.name === "subjectAltName" || t.name === "issuerAltName") {
               t.altNames = [];
               for (var u, a = h.fromDer(t.value), l = 0; l < a.value.length; ++l) {
                  u = a.value[l];
                  var c = {
                     type: u.type,
                     value: u.value
                  };
                  switch (t.altNames.push(c), u.type) {
                     case 1:
                     case 2:
                     case 6:
                        break;
                     case 7:
                        c.ip = q.util.bytesToIP(u.value);
                        break;
                     case 8:
                        c.oid = h.derToOid(u.value);
                        break;
                     default:
                  }
               }
            } else if (t.name === "subjectKeyIdentifier") {
               var a = h.fromDer(t.value);
               t.subjectKeyIdentifier = q.util.bytesToHex(a.value)
            }
         }
         return t
      };
      L.certificationRequestFromAsn1 = function(e, t) {
         var a = {},
            r = [];
         if (!h.validate(e, Yd, a, r)) {
            var n = new Error("Cannot read PKCS#10 certificate request. ASN.1 object is not a PKCS#10 CertificationRequest.");
            throw n.errors = r, n
         }
         var i = h.derToOid(a.publicKeyOid);
         if (i !== L.oids.rsaEncryption) throw new Error("Cannot read public key. OID is not RSA.");
         var s = L.createCertificationRequest();
         if (s.version = a.csrVersion ? a.csrVersion.charCodeAt(0) : 0, s.signatureOid = q.asn1.derToOid(a.csrSignatureOid), s.signatureParameters = Jn(s.signatureOid, a.csrSignatureParams, !0), s.siginfo.algorithmOid = q.asn1.derToOid(a.csrSignatureOid), s.siginfo.parameters = Jn(s.siginfo.algorithmOid, a.csrSignatureParams, !1), s.signature = a.csrSignature, s.certificationRequestInfo = a.certificationRequestInfo, t) {
            s.md = ei({
               signatureOid: s.signatureOid,
               type: "certification request"
            });
            var o = h.toDer(s.certificationRequestInfo);
            s.md.update(o.getBytes())
         }
         var u = q.md.sha1.create();
         return s.subject.getField = function(l) {
            return cr(s.subject, l)
         }, s.subject.addField = function(l) {
            Et([l]), s.subject.attributes.push(l)
         }, s.subject.attributes = L.RDNAttributesAsArray(a.certificationRequestInfoSubject, u), s.subject.hash = u.digest().toHex(), s.publicKey = L.publicKeyFromAsn1(a.subjectPublicKeyInfo), s.getAttribute = function(l) {
            return cr(s, l)
         }, s.addAttribute = function(l) {
            Et([l]), s.attributes.push(l)
         }, s.attributes = L.CRIAttributesAsArray(a.certificationRequestInfoAttributes || []), s
      };
      L.createCertificationRequest = function() {
         var e = {};
         return e.version = 0, e.signatureOid = null, e.signature = null, e.siginfo = {}, e.siginfo.algorithmOid = null, e.subject = {}, e.subject.getField = function(t) {
            return cr(e.subject, t)
         }, e.subject.addField = function(t) {
            Et([t]), e.subject.attributes.push(t)
         }, e.subject.attributes = [], e.subject.hash = null, e.publicKey = null, e.attributes = [], e.getAttribute = function(t) {
            return cr(e, t)
         }, e.addAttribute = function(t) {
            Et([t]), e.attributes.push(t)
         }, e.md = null, e.setSubject = function(t) {
            Et(t), e.subject.attributes = t, e.subject.hash = null
         }, e.setAttributes = function(t) {
            Et(t), e.attributes = t
         }, e.sign = function(t, a) {
            e.md = a || q.md.sha1.create();
            var r = re[e.md.algorithm + "WithRSAEncryption"];
            if (!r) {
               var n = new Error("Could not compute certification request digest. Unknown message digest algorithm OID.");
               throw n.algorithm = e.md.algorithm, n
            }
            e.signatureOid = e.siginfo.algorithmOid = r, e.certificationRequestInfo = L.getCertificationRequestInfo(e);
            var i = h.toDer(e.certificationRequestInfo);
            e.md.update(i.getBytes()), e.signature = t.sign(e.md)
         }, e.verify = function() {
            var t = !1,
               a = e.md;
            if (a === null) {
               a = ei({
                  signatureOid: e.signatureOid,
                  type: "certification request"
               });
               var r = e.certificationRequestInfo || L.getCertificationRequestInfo(e),
                  n = h.toDer(r);
               a.update(n.getBytes())
            }
            return a !== null && (t = Rl({
               certificate: e,
               md: a,
               signature: e.signature
            })), t
         }, e
      };

      function sa(e) {
         for (var t = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, []), a, r, n = e.attributes, i = 0; i < n.length; ++i) {
            a = n[i];
            var s = a.value,
               o = h.Type.PRINTABLESTRING;
            "valueTagClass" in a && (o = a.valueTagClass, o === h.Type.UTF8 && (s = q.util.encodeUtf8(s))), r = h.create(h.Class.UNIVERSAL, h.Type.SET, !0, [h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(a.type).getBytes()), h.create(h.Class.UNIVERSAL, o, !1, s)])]), t.value.push(r)
         }
         return t
      }

      function Et(e) {
         for (var t, a = 0; a < e.length; ++a) {
            if (t = e[a], typeof t.name > "u" && (t.type && t.type in L.oids ? t.name = L.oids[t.type] : t.shortName && t.shortName in Se && (t.name = L.oids[Se[t.shortName]])), typeof t.type > "u")
               if (t.name && t.name in L.oids) t.type = L.oids[t.name];
               else {
                  var r = new Error("Attribute type not specified.");
                  throw r.attribute = t, r
               } if (typeof t.shortName > "u" && t.name && t.name in Se && (t.shortName = Se[t.name]), t.type === re.extensionRequest && (t.valueConstructed = !0, t.valueTagClass = h.Type.SEQUENCE, !t.value && t.extensions)) {
               t.value = [];
               for (var n = 0; n < t.extensions.length; ++n) t.value.push(L.certificateExtensionToAsn1(Ll(t.extensions[n])))
            }
            if (typeof t.value > "u") {
               var r = new Error("Attribute value not specified.");
               throw r.attribute = t, r
            }
         }
      }

      function Ll(e, t) {
         if (t = t || {}, typeof e.name > "u" && e.id && e.id in L.oids && (e.name = L.oids[e.id]), typeof e.id > "u")
            if (e.name && e.name in L.oids) e.id = L.oids[e.name];
            else {
               var a = new Error("Extension ID not specified.");
               throw a.extension = e, a
            } if (typeof e.value < "u") return e;
         if (e.name === "keyUsage") {
            var r = 0,
               n = 0,
               i = 0;
            e.digitalSignature && (n |= 128, r = 7), e.nonRepudiation && (n |= 64, r = 6), e.keyEncipherment && (n |= 32, r = 5), e.dataEncipherment && (n |= 16, r = 4), e.keyAgreement && (n |= 8, r = 3), e.keyCertSign && (n |= 4, r = 2), e.cRLSign && (n |= 2, r = 1), e.encipherOnly && (n |= 1, r = 0), e.decipherOnly && (i |= 128, r = 7);
            var s = String.fromCharCode(r);
            i !== 0 ? s += String.fromCharCode(n) + String.fromCharCode(i) : n !== 0 && (s += String.fromCharCode(n)), e.value = h.create(h.Class.UNIVERSAL, h.Type.BITSTRING, !1, s)
         } else if (e.name === "basicConstraints") e.value = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, []), e.cA && e.value.value.push(h.create(h.Class.UNIVERSAL, h.Type.BOOLEAN, !1, String.fromCharCode(255))), "pathLenConstraint" in e && e.value.value.push(h.create(h.Class.UNIVERSAL, h.Type.INTEGER, !1, h.integerToDer(e.pathLenConstraint).getBytes()));
         else if (e.name === "extKeyUsage") {
            e.value = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, []);
            var o = e.value.value;
            for (var u in e) e[u] === !0 && (u in re ? o.push(h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(re[u]).getBytes())) : u.indexOf(".") !== -1 && o.push(h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(u).getBytes())))
         } else if (e.name === "nsCertType") {
            var r = 0,
               n = 0;
            e.client && (n |= 128, r = 7), e.server && (n |= 64, r = 6), e.email && (n |= 32, r = 5), e.objsign && (n |= 16, r = 4), e.reserved && (n |= 8, r = 3), e.sslCA && (n |= 4, r = 2), e.emailCA && (n |= 2, r = 1), e.objCA && (n |= 1, r = 0);
            var s = String.fromCharCode(r);
            n !== 0 && (s += String.fromCharCode(n)), e.value = h.create(h.Class.UNIVERSAL, h.Type.BITSTRING, !1, s)
         } else if (e.name === "subjectAltName" || e.name === "issuerAltName") {
            e.value = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, []);
            for (var l, c = 0; c < e.altNames.length; ++c) {
               l = e.altNames[c];
               var s = l.value;
               if (l.type === 7 && l.ip) {
                  if (s = q.util.bytesFromIP(l.ip), s === null) {
                     var a = new Error('Extension "ip" value is not a valid IPv4 or IPv6 address.');
                     throw a.extension = e, a
                  }
               } else l.type === 8 && (l.oid ? s = h.oidToDer(h.oidToDer(l.oid)) : s = h.oidToDer(s));
               e.value.value.push(h.create(h.Class.CONTEXT_SPECIFIC, l.type, !1, s))
            }
         } else if (e.name === "nsComment" && t.cert) {
            if (!/^[\x00-\x7F]*$/.test(e.comment) || e.comment.length < 1 || e.comment.length > 128) throw new Error('Invalid "nsComment" content.');
            e.value = h.create(h.Class.UNIVERSAL, h.Type.IA5STRING, !1, e.comment)
         } else if (e.name === "subjectKeyIdentifier" && t.cert) {
            var f = t.cert.generateSubjectKeyIdentifier();
            e.subjectKeyIdentifier = f.toHex(), e.value = h.create(h.Class.UNIVERSAL, h.Type.OCTETSTRING, !1, f.getBytes())
         } else if (e.name === "authorityKeyIdentifier" && t.cert) {
            e.value = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, []);
            var o = e.value.value;
            if (e.keyIdentifier) {
               var y = e.keyIdentifier === !0 ? t.cert.generateSubjectKeyIdentifier().getBytes() : e.keyIdentifier;
               o.push(h.create(h.Class.CONTEXT_SPECIFIC, 0, !1, y))
            }
            if (e.authorityCertIssuer) {
               var g = [h.create(h.Class.CONTEXT_SPECIFIC, 4, !0, [sa(e.authorityCertIssuer === !0 ? t.cert.issuer : e.authorityCertIssuer)])];
               o.push(h.create(h.Class.CONTEXT_SPECIFIC, 1, !0, g))
            }
            if (e.serialNumber) {
               var m = q.util.hexToBytes(e.serialNumber === !0 ? t.cert.serialNumber : e.serialNumber);
               o.push(h.create(h.Class.CONTEXT_SPECIFIC, 2, !1, m))
            }
         } else if (e.name === "cRLDistributionPoints") {
            e.value = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, []);
            for (var o = e.value.value, x = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, []), T = h.create(h.Class.CONTEXT_SPECIFIC, 0, !0, []), l, c = 0; c < e.altNames.length; ++c) {
               l = e.altNames[c];
               var s = l.value;
               if (l.type === 7 && l.ip) {
                  if (s = q.util.bytesFromIP(l.ip), s === null) {
                     var a = new Error('Extension "ip" value is not a valid IPv4 or IPv6 address.');
                     throw a.extension = e, a
                  }
               } else l.type === 8 && (l.oid ? s = h.oidToDer(h.oidToDer(l.oid)) : s = h.oidToDer(s));
               T.value.push(h.create(h.Class.CONTEXT_SPECIFIC, l.type, !1, s))
            }
            x.value.push(h.create(h.Class.CONTEXT_SPECIFIC, 0, !0, [T])), o.push(x)
         }
         if (typeof e.value > "u") {
            var a = new Error("Extension value not specified.");
            throw a.extension = e, a
         }
         return e
      }

      function bs(e, t) {
         switch (e) {
            case re["RSASSA-PSS"]:
               var a = [];
               return t.hash.algorithmOid !== void 0 && a.push(h.create(h.Class.CONTEXT_SPECIFIC, 0, !0, [h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(t.hash.algorithmOid).getBytes()), h.create(h.Class.UNIVERSAL, h.Type.NULL, !1, "")])])), t.mgf.algorithmOid !== void 0 && a.push(h.create(h.Class.CONTEXT_SPECIFIC, 1, !0, [h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(t.mgf.algorithmOid).getBytes()), h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(t.mgf.hash.algorithmOid).getBytes()), h.create(h.Class.UNIVERSAL, h.Type.NULL, !1, "")])])])), t.saltLength !== void 0 && a.push(h.create(h.Class.CONTEXT_SPECIFIC, 2, !0, [h.create(h.Class.UNIVERSAL, h.Type.INTEGER, !1, h.integerToDer(t.saltLength).getBytes())])), h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, a);
            default:
               return h.create(h.Class.UNIVERSAL, h.Type.NULL, !1, "")
         }
      }

      function Zd(e) {
         var t = h.create(h.Class.CONTEXT_SPECIFIC, 0, !0, []);
         if (e.attributes.length === 0) return t;
         for (var a = e.attributes, r = 0; r < a.length; ++r) {
            var n = a[r],
               i = n.value,
               s = h.Type.UTF8;
            "valueTagClass" in n && (s = n.valueTagClass), s === h.Type.UTF8 && (i = q.util.encodeUtf8(i));
            var o = !1;
            "valueConstructed" in n && (o = n.valueConstructed);
            var u = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(n.type).getBytes()), h.create(h.Class.UNIVERSAL, h.Type.SET, !0, [h.create(h.Class.UNIVERSAL, s, o, i)])]);
            t.value.push(u)
         }
         return t
      }
      var Qd = new Date("1950-01-01T00:00:00Z"),
         $d = new Date("2050-01-01T00:00:00Z");

      function _l(e) {
         return e >= Qd && e < $d ? h.create(h.Class.UNIVERSAL, h.Type.UTCTIME, !1, h.dateToUtcTime(e)) : h.create(h.Class.UNIVERSAL, h.Type.GENERALIZEDTIME, !1, h.dateToGeneralizedTime(e))
      }
      L.getTBSCertificate = function(e) {
         var t = _l(e.validity.notBefore),
            a = _l(e.validity.notAfter),
            r = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [h.create(h.Class.CONTEXT_SPECIFIC, 0, !0, [h.create(h.Class.UNIVERSAL, h.Type.INTEGER, !1, h.integerToDer(e.version).getBytes())]), h.create(h.Class.UNIVERSAL, h.Type.INTEGER, !1, q.util.hexToBytes(e.serialNumber)), h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(e.siginfo.algorithmOid).getBytes()), bs(e.siginfo.algorithmOid, e.siginfo.parameters)]), sa(e.issuer), h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [t, a]), sa(e.subject), L.publicKeyToAsn1(e.publicKey)]);
         return e.issuer.uniqueId && r.value.push(h.create(h.Class.CONTEXT_SPECIFIC, 1, !0, [h.create(h.Class.UNIVERSAL, h.Type.BITSTRING, !1, String.fromCharCode(0) + e.issuer.uniqueId)])), e.subject.uniqueId && r.value.push(h.create(h.Class.CONTEXT_SPECIFIC, 2, !0, [h.create(h.Class.UNIVERSAL, h.Type.BITSTRING, !1, String.fromCharCode(0) + e.subject.uniqueId)])), e.extensions.length > 0 && r.value.push(L.certificateExtensionsToAsn1(e.extensions)), r
      };
      L.getCertificationRequestInfo = function(e) {
         var t = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [h.create(h.Class.UNIVERSAL, h.Type.INTEGER, !1, h.integerToDer(e.version).getBytes()), sa(e.subject), L.publicKeyToAsn1(e.publicKey), Zd(e)]);
         return t
      };
      L.distinguishedNameToAsn1 = function(e) {
         return sa(e)
      };
      L.certificateToAsn1 = function(e) {
         var t = e.tbsCertificate || L.getTBSCertificate(e);
         return h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [t, h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(e.signatureOid).getBytes()), bs(e.signatureOid, e.signatureParameters)]), h.create(h.Class.UNIVERSAL, h.Type.BITSTRING, !1, String.fromCharCode(0) + e.signature)])
      };
      L.certificateExtensionsToAsn1 = function(e) {
         var t = h.create(h.Class.CONTEXT_SPECIFIC, 3, !0, []),
            a = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, []);
         t.value.push(a);
         for (var r = 0; r < e.length; ++r) a.value.push(L.certificateExtensionToAsn1(e[r]));
         return t
      };
      L.certificateExtensionToAsn1 = function(e) {
         var t = h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, []);
         t.value.push(h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(e.id).getBytes())), e.critical && t.value.push(h.create(h.Class.UNIVERSAL, h.Type.BOOLEAN, !1, String.fromCharCode(255)));
         var a = e.value;
         return typeof e.value != "string" && (a = h.toDer(a).getBytes()), t.value.push(h.create(h.Class.UNIVERSAL, h.Type.OCTETSTRING, !1, a)), t
      };
      L.certificationRequestToAsn1 = function(e) {
         var t = e.certificationRequestInfo || L.getCertificationRequestInfo(e);
         return h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [t, h.create(h.Class.UNIVERSAL, h.Type.SEQUENCE, !0, [h.create(h.Class.UNIVERSAL, h.Type.OID, !1, h.oidToDer(e.signatureOid).getBytes()), bs(e.signatureOid, e.signatureParameters)]), h.create(h.Class.UNIVERSAL, h.Type.BITSTRING, !1, String.fromCharCode(0) + e.signature)])
      };
      L.createCaStore = function(e) {
         var t = {
            certs: {}
         };
         t.getIssuer = function(s) {
            var o = a(s.issuer);
            return o
         }, t.addCertificate = function(s) {
            if (typeof s == "string" && (s = q.pki.certificateFromPem(s)), r(s.subject), !t.hasCertificate(s))
               if (s.subject.hash in t.certs) {
                  var o = t.certs[s.subject.hash];
                  q.util.isArray(o) || (o = [o]), o.push(s), t.certs[s.subject.hash] = o
               } else t.certs[s.subject.hash] = s
         }, t.hasCertificate = function(s) {
            typeof s == "string" && (s = q.pki.certificateFromPem(s));
            var o = a(s.subject);
            if (!o) return !1;
            q.util.isArray(o) || (o = [o]);
            for (var u = h.toDer(L.certificateToAsn1(s)).getBytes(), l = 0; l < o.length; ++l) {
               var c = h.toDer(L.certificateToAsn1(o[l])).getBytes();
               if (u === c) return !0
            }
            return !1
         }, t.listAllCertificates = function() {
            var s = [];
            for (var o in t.certs)
               if (t.certs.hasOwnProperty(o)) {
                  var u = t.certs[o];
                  if (!q.util.isArray(u)) s.push(u);
                  else
                     for (var l = 0; l < u.length; ++l) s.push(u[l])
               } return s
         }, t.removeCertificate = function(s) {
            var o;
            if (typeof s == "string" && (s = q.pki.certificateFromPem(s)), r(s.subject), !t.hasCertificate(s)) return null;
            var u = a(s.subject);
            if (!q.util.isArray(u)) return o = t.certs[s.subject.hash], delete t.certs[s.subject.hash], o;
            for (var l = h.toDer(L.certificateToAsn1(s)).getBytes(), c = 0; c < u.length; ++c) {
               var f = h.toDer(L.certificateToAsn1(u[c])).getBytes();
               l === f && (o = u[c], u.splice(c, 1))
            }
            return u.length === 0 && delete t.certs[s.subject.hash], o
         };

         function a(s) {
            return r(s), t.certs[s.hash] || null
         }

         function r(s) {
            if (!s.hash) {
               var o = q.md.sha1.create();
               s.attributes = L.RDNAttributesAsArray(sa(s), o), s.hash = o.digest().toHex()
            }
         }
         if (e)
            for (var n = 0; n < e.length; ++n) {
               var i = e[n];
               t.addCertificate(i)
            }
         return t
      };
      L.certificateError = {
         bad_certificate: "forge.pki.BadCertificate",
         unsupported_certificate: "forge.pki.UnsupportedCertificate",
         certificate_revoked: "forge.pki.CertificateRevoked",
         certificate_expired: "forge.pki.CertificateExpired",
         certificate_unknown: "forge.pki.CertificateUnknown",
         unknown_ca: "forge.pki.UnknownCertificateAuthority"
      };
      L.verifyCertificateChain = function(e, t, a) {
         typeof a == "function" && (a = {
            verify: a
         }), a = a || {}, t = t.slice(0);
         var r = t.slice(0),
            n = a.validityCheckDate;
         typeof n > "u" && (n = new Date);
         var i = !0,
            s = null,
            o = 0;
         do {
            var u = t.shift(),
               l = null,
               c = !1;
            if (n && (n < u.validity.notBefore || n > u.validity.notAfter) && (s = {
                  message: "Certificate is not valid yet or has expired.",
                  error: L.certificateError.certificate_expired,
                  notBefore: u.validity.notBefore,
                  notAfter: u.validity.notAfter,
                  now: n
               }), s === null) {
               if (l = t[0] || e.getIssuer(u), l === null && u.isIssuer(u) && (c = !0, l = u), l) {
                  var f = l;
                  q.util.isArray(f) || (f = [f]);
                  for (var y = !1; !y && f.length > 0;) {
                     l = f.shift();
                     try {
                        y = l.verify(u)
                     } catch {}
                  }
                  y || (s = {
                     message: "Certificate signature is invalid.",
                     error: L.certificateError.bad_certificate
                  })
               }
               s === null && (!l || c) && !e.hasCertificate(u) && (s = {
                  message: "Certificate is not trusted.",
                  error: L.certificateError.unknown_ca
               })
            }
            if (s === null && l && !u.isIssuer(l) && (s = {
                  message: "Certificate issuer is invalid.",
                  error: L.certificateError.bad_certificate
               }), s === null)
               for (var g = {
                     keyUsage: !0,
                     basicConstraints: !0
                  }, m = 0; s === null && m < u.extensions.length; ++m) {
                  var x = u.extensions[m];
                  x.critical && !(x.name in g) && (s = {
                     message: "Certificate has an unsupported critical extension.",
                     error: L.certificateError.unsupported_certificate
                  })
               }
            if (s === null && (!i || t.length === 0 && (!l || c))) {
               var T = u.getExtension("basicConstraints"),
                  I = u.getExtension("keyUsage");
               if (I !== null && (!I.keyCertSign || T === null) && (s = {
                     message: "Certificate keyUsage or basicConstraints conflict or indicate that the certificate is not a CA. If the certificate is the only one in the chain or isn't the first then the certificate must be a valid CA.",
                     error: L.certificateError.bad_certificate
                  }), s === null && T !== null && !T.cA && (s = {
                     message: "Certificate basicConstraints indicates the certificate is not a CA.",
                     error: L.certificateError.bad_certificate
                  }), s === null && I !== null && "pathLenConstraint" in T) {
                  var A = o - 1;
                  A > T.pathLenConstraint && (s = {
                     message: "Certificate basicConstraints pathLenConstraint violated.",
                     error: L.certificateError.bad_certificate
                  })
               }
            }
            var B = s === null ? !0 : s.error,
               F = a.verify ? a.verify(B, o, r) : B;
            if (F === !0) s = null;
            else throw B === !0 && (s = {
               message: "The application rejected the certificate.",
               error: L.certificateError.bad_certificate
            }), (F || F === 0) && (typeof F == "object" && !q.util.isArray(F) ? (F.message && (s.message = F.message), F.error && (s.error = F.error)) : typeof F == "string" && (s.error = F)), s;
            i = !1, ++o
         } while (t.length > 0);
         return !0
      }
   });
   var Bs = Y((Ug, Ul) => {
      "use strict";
      var me = $();
      wt();
      Jr();
      or();
      Ss();
      Ts();
      mt();
      rn();
      aa();
      ae();
      ti();
      var v = me.asn1,
         X = me.pki,
         nn = Ul.exports = me.pkcs12 = me.pkcs12 || {},
         Ol = {
            name: "ContentInfo",
            tagClass: v.Class.UNIVERSAL,
            type: v.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "ContentInfo.contentType",
               tagClass: v.Class.UNIVERSAL,
               type: v.Type.OID,
               constructed: !1,
               capture: "contentType"
            }, {
               name: "ContentInfo.content",
               tagClass: v.Class.CONTEXT_SPECIFIC,
               constructed: !0,
               captureAsn1: "content"
            }]
         },
         jd = {
            name: "PFX",
            tagClass: v.Class.UNIVERSAL,
            type: v.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "PFX.version",
               tagClass: v.Class.UNIVERSAL,
               type: v.Type.INTEGER,
               constructed: !1,
               capture: "version"
            }, Ol, {
               name: "PFX.macData",
               tagClass: v.Class.UNIVERSAL,
               type: v.Type.SEQUENCE,
               constructed: !0,
               optional: !0,
               captureAsn1: "mac",
               value: [{
                  name: "PFX.macData.mac",
                  tagClass: v.Class.UNIVERSAL,
                  type: v.Type.SEQUENCE,
                  constructed: !0,
                  value: [{
                     name: "PFX.macData.mac.digestAlgorithm",
                     tagClass: v.Class.UNIVERSAL,
                     type: v.Type.SEQUENCE,
                     constructed: !0,
                     value: [{
                        name: "PFX.macData.mac.digestAlgorithm.algorithm",
                        tagClass: v.Class.UNIVERSAL,
                        type: v.Type.OID,
                        constructed: !1,
                        capture: "macAlgorithm"
                     }, {
                        name: "PFX.macData.mac.digestAlgorithm.parameters",
                        tagClass: v.Class.UNIVERSAL,
                        captureAsn1: "macAlgorithmParameters"
                     }]
                  }, {
                     name: "PFX.macData.mac.digest",
                     tagClass: v.Class.UNIVERSAL,
                     type: v.Type.OCTETSTRING,
                     constructed: !1,
                     capture: "macDigest"
                  }]
               }, {
                  name: "PFX.macData.macSalt",
                  tagClass: v.Class.UNIVERSAL,
                  type: v.Type.OCTETSTRING,
                  constructed: !1,
                  capture: "macSalt"
               }, {
                  name: "PFX.macData.iterations",
                  tagClass: v.Class.UNIVERSAL,
                  type: v.Type.INTEGER,
                  constructed: !1,
                  optional: !0,
                  capture: "macIterations"
               }]
            }]
         },
         Xd = {
            name: "SafeBag",
            tagClass: v.Class.UNIVERSAL,
            type: v.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "SafeBag.bagId",
               tagClass: v.Class.UNIVERSAL,
               type: v.Type.OID,
               constructed: !1,
               capture: "bagId"
            }, {
               name: "SafeBag.bagValue",
               tagClass: v.Class.CONTEXT_SPECIFIC,
               constructed: !0,
               captureAsn1: "bagValue"
            }, {
               name: "SafeBag.bagAttributes",
               tagClass: v.Class.UNIVERSAL,
               type: v.Type.SET,
               constructed: !0,
               optional: !0,
               capture: "bagAttributes"
            }]
         },
         Jd = {
            name: "Attribute",
            tagClass: v.Class.UNIVERSAL,
            type: v.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "Attribute.attrId",
               tagClass: v.Class.UNIVERSAL,
               type: v.Type.OID,
               constructed: !1,
               capture: "oid"
            }, {
               name: "Attribute.attrValues",
               tagClass: v.Class.UNIVERSAL,
               type: v.Type.SET,
               constructed: !0,
               capture: "values"
            }]
         },
         ep = {
            name: "CertBag",
            tagClass: v.Class.UNIVERSAL,
            type: v.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "CertBag.certId",
               tagClass: v.Class.UNIVERSAL,
               type: v.Type.OID,
               constructed: !1,
               capture: "certId"
            }, {
               name: "CertBag.certValue",
               tagClass: v.Class.CONTEXT_SPECIFIC,
               constructed: !0,
               value: [{
                  name: "CertBag.certValue[0]",
                  tagClass: v.Class.UNIVERSAL,
                  type: v.Class.OCTETSTRING,
                  constructed: !1,
                  capture: "cert"
               }]
            }]
         };

      function an(e, t, a, r) {
         for (var n = [], i = 0; i < e.length; i++)
            for (var s = 0; s < e[i].safeBags.length; s++) {
               var o = e[i].safeBags[s];
               if (!(r !== void 0 && o.type !== r)) {
                  if (t === null) {
                     n.push(o);
                     continue
                  }
                  o.attributes[t] !== void 0 && o.attributes[t].indexOf(a) >= 0 && n.push(o)
               }
            }
         return n
      }
      nn.pkcs12FromAsn1 = function(e, t, a) {
         typeof t == "string" ? (a = t, t = !0) : t === void 0 && (t = !0);
         var r = {},
            n = [];
         if (!v.validate(e, jd, r, n)) {
            var i = new Error("Cannot read PKCS#12 PFX. ASN.1 object is not an PKCS#12 PFX.");
            throw i.errors = i, i
         }
         var s = {
            version: r.version.charCodeAt(0),
            safeContents: [],
            getBags: function(T) {
               var I = {},
                  A;
               return "localKeyId" in T ? A = T.localKeyId : "localKeyIdHex" in T && (A = me.util.hexToBytes(T.localKeyIdHex)), A === void 0 && !("friendlyName" in T) && "bagType" in T && (I[T.bagType] = an(s.safeContents, null, null, T.bagType)), A !== void 0 && (I.localKeyId = an(s.safeContents, "localKeyId", A, T.bagType)), "friendlyName" in T && (I.friendlyName = an(s.safeContents, "friendlyName", T.friendlyName, T.bagType)), I
            },
            getBagsByFriendlyName: function(T, I) {
               return an(s.safeContents, "friendlyName", T, I)
            },
            getBagsByLocalKeyId: function(T, I) {
               return an(s.safeContents, "localKeyId", T, I)
            }
         };
         if (r.version.charCodeAt(0) !== 3) {
            var i = new Error("PKCS#12 PFX of version other than 3 not supported.");
            throw i.version = r.version.charCodeAt(0), i
         }
         if (v.derToOid(r.contentType) !== X.oids.data) {
            var i = new Error("Only PKCS#12 PFX in password integrity mode supported.");
            throw i.oid = v.derToOid(r.contentType), i
         }
         var o = r.content.value[0];
         if (o.tagClass !== v.Class.UNIVERSAL || o.type !== v.Type.OCTETSTRING) throw new Error("PKCS#12 authSafe content data is not an OCTET STRING.");
         if (o = As(o), r.mac) {
            var u = null,
               l = 0,
               c = v.derToOid(r.macAlgorithm);
            switch (c) {
               case X.oids.sha1:
                  u = me.md.sha1.create(), l = 20;
                  break;
               case X.oids.sha256:
                  u = me.md.sha256.create(), l = 32;
                  break;
               case X.oids.sha384:
                  u = me.md.sha384.create(), l = 48;
                  break;
               case X.oids.sha512:
                  u = me.md.sha512.create(), l = 64;
                  break;
               case X.oids.md5:
                  u = me.md.md5.create(), l = 16;
                  break
            }
            if (u === null) throw new Error("PKCS#12 uses unsupported MAC algorithm: " + c);
            var f = new me.util.ByteBuffer(r.macSalt),
               y = "macIterations" in r ? parseInt(me.util.bytesToHex(r.macIterations), 16) : 1,
               g = nn.generateKey(a, f, 3, y, l, u),
               m = me.hmac.create();
            m.start(u, g), m.update(o.value);
            var x = m.getMac();
            if (x.getBytes() !== r.macDigest) throw new Error("PKCS#12 MAC could not be verified. Invalid password?")
         }
         return tp(s, o.value, t, a), s
      };

      function As(e) {
         if (e.composed || e.constructed) {
            for (var t = me.util.createBuffer(), a = 0; a < e.value.length; ++a) t.putBytes(e.value[a].value);
            e.composed = e.constructed = !1, e.value = t.getBytes()
         }
         return e
      }

      function tp(e, t, a, r) {
         if (t = v.fromDer(t, a), t.tagClass !== v.Class.UNIVERSAL || t.type !== v.Type.SEQUENCE || t.constructed !== !0) throw new Error("PKCS#12 AuthenticatedSafe expected to be a SEQUENCE OF ContentInfo");
         for (var n = 0; n < t.value.length; n++) {
            var i = t.value[n],
               s = {},
               o = [];
            if (!v.validate(i, Ol, s, o)) {
               var u = new Error("Cannot read ContentInfo.");
               throw u.errors = o, u
            }
            var l = {
                  encrypted: !1
               },
               c = null,
               f = s.content.value[0];
            switch (v.derToOid(s.contentType)) {
               case X.oids.data:
                  if (f.tagClass !== v.Class.UNIVERSAL || f.type !== v.Type.OCTETSTRING) throw new Error("PKCS#12 SafeContents Data is not an OCTET STRING.");
                  c = As(f).value;
                  break;
               case X.oids.encryptedData:
                  c = rp(f, r), l.encrypted = !0;
                  break;
               default:
                  var u = new Error("Unsupported PKCS#12 contentType.");
                  throw u.contentType = v.derToOid(s.contentType), u
            }
            l.safeBags = ap(c, a, r), e.safeContents.push(l)
         }
      }

      function rp(e, t) {
         var a = {},
            r = [];
         if (!v.validate(e, me.pkcs7.asn1.encryptedDataValidator, a, r)) {
            var n = new Error("Cannot read EncryptedContentInfo.");
            throw n.errors = r, n
         }
         var i = v.derToOid(a.contentType);
         if (i !== X.oids.data) {
            var n = new Error("PKCS#12 EncryptedContentInfo ContentType is not Data.");
            throw n.oid = i, n
         }
         i = v.derToOid(a.encAlgorithm);
         var s = X.pbe.getCipher(i, a.encParameter, t),
            o = As(a.encryptedContentAsn1),
            u = me.util.createBuffer(o.value);
         if (s.update(u), !s.finish()) throw new Error("Failed to decrypt PKCS#12 SafeContents.");
         return s.output.getBytes()
      }

      function ap(e, t, a) {
         if (!t && e.length === 0) return [];
         if (e = v.fromDer(e, t), e.tagClass !== v.Class.UNIVERSAL || e.type !== v.Type.SEQUENCE || e.constructed !== !0) throw new Error("PKCS#12 SafeContents expected to be a SEQUENCE OF SafeBag.");
         for (var r = [], n = 0; n < e.value.length; n++) {
            var i = e.value[n],
               s = {},
               o = [];
            if (!v.validate(i, Xd, s, o)) {
               var u = new Error("Cannot read SafeBag.");
               throw u.errors = o, u
            }
            var l = {
               type: v.derToOid(s.bagId),
               attributes: np(s.bagAttributes)
            };
            r.push(l);
            var c, f, y = s.bagValue.value[0];
            switch (l.type) {
               case X.oids.pkcs8ShroudedKeyBag:
                  if (y = X.decryptPrivateKeyInfo(y, a), y === null) throw new Error("Unable to decrypt PKCS#8 ShroudedKeyBag, wrong password?");
               case X.oids.keyBag:
                  try {
                     l.key = X.privateKeyFromAsn1(y)
                  } catch {
                     l.key = null, l.asn1 = y
                  }
                  continue;
               case X.oids.certBag:
                  c = ep, f = function() {
                     if (v.derToOid(s.certId) !== X.oids.x509Certificate) {
                        var m = new Error("Unsupported certificate type, only X.509 supported.");
                        throw m.oid = v.derToOid(s.certId), m
                     }
                     var x = v.fromDer(s.cert, t);
                     try {
                        l.cert = X.certificateFromAsn1(x, !0)
                     } catch {
                        l.cert = null, l.asn1 = x
                     }
                  };
                  break;
               default:
                  var u = new Error("Unsupported PKCS#12 SafeBag type.");
                  throw u.oid = l.type, u
            }
            if (c !== void 0 && !v.validate(y, c, s, o)) {
               var u = new Error("Cannot read PKCS#12 " + c.name);
               throw u.errors = o, u
            }
            f()
         }
         return r
      }

      function np(e) {
         var t = {};
         if (e !== void 0)
            for (var a = 0; a < e.length; ++a) {
               var r = {},
                  n = [];
               if (!v.validate(e[a], Jd, r, n)) {
                  var i = new Error("Cannot read PKCS#12 BagAttribute.");
                  throw i.errors = n, i
               }
               var s = v.derToOid(r.oid);
               if (X.oids[s] !== void 0) {
                  t[X.oids[s]] = [];
                  for (var o = 0; o < r.values.length; ++o) t[X.oids[s]].push(r.values[o].value)
               }
            }
         return t
      }
      nn.toPkcs12Asn1 = function(e, t, a, r) {
         r = r || {}, r.saltSize = r.saltSize || 8, r.count = r.count || 2048, r.algorithm = r.algorithm || r.encAlgorithm || "aes128", "useMac" in r || (r.useMac = !0), "localKeyId" in r || (r.localKeyId = null), "generateLocalKeyId" in r || (r.generateLocalKeyId = !0);
         var n = r.localKeyId,
            i;
         if (n !== null) n = me.util.hexToBytes(n);
         else if (r.generateLocalKeyId)
            if (t) {
               var s = me.util.isArray(t) ? t[0] : t;
               typeof s == "string" && (s = X.certificateFromPem(s));
               var o = me.md.sha1.create();
               o.update(v.toDer(X.certificateToAsn1(s)).getBytes()), n = o.digest().getBytes()
            } else n = me.random.getBytes(20);
         var u = [];
         n !== null && u.push(v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.OID, !1, v.oidToDer(X.oids.localKeyId).getBytes()), v.create(v.Class.UNIVERSAL, v.Type.SET, !0, [v.create(v.Class.UNIVERSAL, v.Type.OCTETSTRING, !1, n)])])), "friendlyName" in r && u.push(v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.OID, !1, v.oidToDer(X.oids.friendlyName).getBytes()), v.create(v.Class.UNIVERSAL, v.Type.SET, !0, [v.create(v.Class.UNIVERSAL, v.Type.BMPSTRING, !1, r.friendlyName)])])), u.length > 0 && (i = v.create(v.Class.UNIVERSAL, v.Type.SET, !0, u));
         var l = [],
            c = [];
         t !== null && (me.util.isArray(t) ? c = t : c = [t]);
         for (var f = [], y = 0; y < c.length; ++y) {
            t = c[y], typeof t == "string" && (t = X.certificateFromPem(t));
            var g = y === 0 ? i : void 0,
               m = X.certificateToAsn1(t),
               x = v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.OID, !1, v.oidToDer(X.oids.certBag).getBytes()), v.create(v.Class.CONTEXT_SPECIFIC, 0, !0, [v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.OID, !1, v.oidToDer(X.oids.x509Certificate).getBytes()), v.create(v.Class.CONTEXT_SPECIFIC, 0, !0, [v.create(v.Class.UNIVERSAL, v.Type.OCTETSTRING, !1, v.toDer(m).getBytes())])])]), g]);
            f.push(x)
         }
         if (f.length > 0) {
            var T = v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, f),
               I = v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.OID, !1, v.oidToDer(X.oids.data).getBytes()), v.create(v.Class.CONTEXT_SPECIFIC, 0, !0, [v.create(v.Class.UNIVERSAL, v.Type.OCTETSTRING, !1, v.toDer(T).getBytes())])]);
            l.push(I)
         }
         var A = null;
         if (e !== null) {
            var B = X.wrapRsaPrivateKey(X.privateKeyToAsn1(e));
            a === null ? A = v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.OID, !1, v.oidToDer(X.oids.keyBag).getBytes()), v.create(v.Class.CONTEXT_SPECIFIC, 0, !0, [B]), i]) : A = v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.OID, !1, v.oidToDer(X.oids.pkcs8ShroudedKeyBag).getBytes()), v.create(v.Class.CONTEXT_SPECIFIC, 0, !0, [X.encryptPrivateKeyInfo(B, a, r)]), i]);
            var F = v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [A]),
               R = v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.OID, !1, v.oidToDer(X.oids.data).getBytes()), v.create(v.Class.CONTEXT_SPECIFIC, 0, !0, [v.create(v.Class.UNIVERSAL, v.Type.OCTETSTRING, !1, v.toDer(F).getBytes())])]);
            l.push(R)
         }
         var D = v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, l),
            G;
         if (r.useMac) {
            var o = me.md.sha1.create(),
               z = new me.util.ByteBuffer(me.random.getBytes(r.saltSize)),
               oe = r.count,
               e = nn.generateKey(a, z, 3, oe, 20),
               ce = me.hmac.create();
            ce.start(o, e), ce.update(v.toDer(D).getBytes());
            var pe = ce.getMac();
            G = v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.OID, !1, v.oidToDer(X.oids.sha1).getBytes()), v.create(v.Class.UNIVERSAL, v.Type.NULL, !1, "")]), v.create(v.Class.UNIVERSAL, v.Type.OCTETSTRING, !1, pe.getBytes())]), v.create(v.Class.UNIVERSAL, v.Type.OCTETSTRING, !1, z.getBytes()), v.create(v.Class.UNIVERSAL, v.Type.INTEGER, !1, v.integerToDer(oe).getBytes())])
         }
         return v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.INTEGER, !1, v.integerToDer(3).getBytes()), v.create(v.Class.UNIVERSAL, v.Type.SEQUENCE, !0, [v.create(v.Class.UNIVERSAL, v.Type.OID, !1, v.oidToDer(X.oids.data).getBytes()), v.create(v.Class.CONTEXT_SPECIFIC, 0, !0, [v.create(v.Class.UNIVERSAL, v.Type.OCTETSTRING, !1, v.toDer(D).getBytes())])]), G])
      };
      nn.generateKey = me.pbe.generatePkcs12Key
   });
   var Ns = Y((Fg, Fl) => {
      "use strict";
      var fr = $();
      wt();
      or();
      Ts();
      Sr();
      zn();
      Bs();
      Xn();
      rn();
      ae();
      ti();
      var ws = fr.asn1,
         oa = Fl.exports = fr.pki = fr.pki || {};
      oa.pemToDer = function(e) {
         var t = fr.pem.decode(e)[0];
         if (t.procType && t.procType.type === "ENCRYPTED") throw new Error("Could not convert PEM to DER; PEM is encrypted.");
         return fr.util.createBuffer(t.body)
      };
      oa.privateKeyFromPem = function(e) {
         var t = fr.pem.decode(e)[0];
         if (t.type !== "PRIVATE KEY" && t.type !== "RSA PRIVATE KEY") {
            var a = new Error('Could not convert private key from PEM; PEM header type is not "PRIVATE KEY" or "RSA PRIVATE KEY".');
            throw a.headerType = t.type, a
         }
         if (t.procType && t.procType.type === "ENCRYPTED") throw new Error("Could not convert private key from PEM; PEM is encrypted.");
         var r = ws.fromDer(t.body);
         return oa.privateKeyFromAsn1(r)
      };
      oa.privateKeyToPem = function(e, t) {
         var a = {
            type: "RSA PRIVATE KEY",
            body: ws.toDer(oa.privateKeyToAsn1(e)).getBytes()
         };
         return fr.pem.encode(a, {
            maxline: t
         })
      };
      oa.privateKeyInfoToPem = function(e, t) {
         var a = {
            type: "PRIVATE KEY",
            body: ws.toDer(e).getBytes()
         };
         return fr.pem.encode(a, {
            maxline: t
         })
      }
   });
   var Os = Y((Pg, zl) => {
      "use strict";
      var N = $();
      wt();
      Jr();
      Kn();
      Sr();
      Ns();
      mt();
      aa();
      ae();
      var ii = function(e, t, a, r) {
            var n = N.util.createBuffer(),
               i = e.length >> 1,
               s = i + (e.length & 1),
               o = e.substr(0, s),
               u = e.substr(i, s),
               l = N.util.createBuffer(),
               c = N.hmac.create();
            a = t + a;
            var f = Math.ceil(r / 16),
               y = Math.ceil(r / 20);
            c.start("MD5", o);
            var g = N.util.createBuffer();
            l.putBytes(a);
            for (var m = 0; m < f; ++m) c.start(null, null), c.update(l.getBytes()), l.putBuffer(c.digest()), c.start(null, null), c.update(l.bytes() + a), g.putBuffer(c.digest());
            c.start("SHA1", u);
            var x = N.util.createBuffer();
            l.clear(), l.putBytes(a);
            for (var m = 0; m < y; ++m) c.start(null, null), c.update(l.getBytes()), l.putBuffer(c.digest()), c.start(null, null), c.update(l.bytes() + a), x.putBuffer(c.digest());
            return n.putBytes(N.util.xorBytes(g.getBytes(), x.getBytes(), r)), n
         },
         ip = function(e, t, a) {
            var r = N.hmac.create();
            r.start("SHA1", e);
            var n = N.util.createBuffer();
            return n.putInt32(t[0]), n.putInt32(t[1]), n.putByte(a.type), n.putByte(a.version.major), n.putByte(a.version.minor), n.putInt16(a.length), n.putBytes(a.fragment.bytes()), r.update(n.getBytes()), r.digest().getBytes()
         },
         sp = function(e, t, a) {
            var r = !1;
            try {
               var n = e.deflate(t.fragment.getBytes());
               t.fragment = N.util.createBuffer(n), t.length = n.length, r = !0
            } catch {}
            return r
         },
         op = function(e, t, a) {
            var r = !1;
            try {
               var n = e.inflate(t.fragment.getBytes());
               t.fragment = N.util.createBuffer(n), t.length = n.length, r = !0
            } catch {}
            return r
         },
         lt = function(e, t) {
            var a = 0;
            switch (t) {
               case 1:
                  a = e.getByte();
                  break;
               case 2:
                  a = e.getInt16();
                  break;
               case 3:
                  a = e.getInt24();
                  break;
               case 4:
                  a = e.getInt32();
                  break
            }
            return N.util.createBuffer(e.getBytes(a))
         },
         Ct = function(e, t, a) {
            e.putInt(a.length(), t << 3), e.putBuffer(a)
         },
         p = {};
      p.Versions = {
         TLS_1_0: {
            major: 3,
            minor: 1
         },
         TLS_1_1: {
            major: 3,
            minor: 2
         },
         TLS_1_2: {
            major: 3,
            minor: 3
         }
      };
      p.SupportedVersions = [p.Versions.TLS_1_1, p.Versions.TLS_1_0];
      p.Version = p.SupportedVersions[0];
      p.MaxFragment = 16384 - 1024;
      p.ConnectionEnd = {
         server: 0,
         client: 1
      };
      p.PRFAlgorithm = {
         tls_prf_sha256: 0
      };
      p.BulkCipherAlgorithm = {
         none: null,
         rc4: 0,
         des3: 1,
         aes: 2
      };
      p.CipherType = {
         stream: 0,
         block: 1,
         aead: 2
      };
      p.MACAlgorithm = {
         none: null,
         hmac_md5: 0,
         hmac_sha1: 1,
         hmac_sha256: 2,
         hmac_sha384: 3,
         hmac_sha512: 4
      };
      p.CompressionMethod = {
         none: 0,
         deflate: 1
      };
      p.ContentType = {
         change_cipher_spec: 20,
         alert: 21,
         handshake: 22,
         application_data: 23,
         heartbeat: 24
      };
      p.HandshakeType = {
         hello_request: 0,
         client_hello: 1,
         server_hello: 2,
         certificate: 11,
         server_key_exchange: 12,
         certificate_request: 13,
         server_hello_done: 14,
         certificate_verify: 15,
         client_key_exchange: 16,
         finished: 20
      };
      p.Alert = {};
      p.Alert.Level = {
         warning: 1,
         fatal: 2
      };
      p.Alert.Description = {
         close_notify: 0,
         unexpected_message: 10,
         bad_record_mac: 20,
         decryption_failed: 21,
         record_overflow: 22,
         decompression_failure: 30,
         handshake_failure: 40,
         bad_certificate: 42,
         unsupported_certificate: 43,
         certificate_revoked: 44,
         certificate_expired: 45,
         certificate_unknown: 46,
         illegal_parameter: 47,
         unknown_ca: 48,
         access_denied: 49,
         decode_error: 50,
         decrypt_error: 51,
         export_restriction: 60,
         protocol_version: 70,
         insufficient_security: 71,
         internal_error: 80,
         user_canceled: 90,
         no_renegotiation: 100
      };
      p.HeartbeatMessageType = {
         heartbeat_request: 1,
         heartbeat_response: 2
      };
      p.CipherSuites = {};
      p.getCipherSuite = function(e) {
         var t = null;
         for (var a in p.CipherSuites) {
            var r = p.CipherSuites[a];
            if (r.id[0] === e.charCodeAt(0) && r.id[1] === e.charCodeAt(1)) {
               t = r;
               break
            }
         }
         return t
      };
      p.handleUnexpected = function(e, t) {
         var a = !e.open && e.entity === p.ConnectionEnd.client;
         a || e.error(e, {
            message: "Unexpected message. Received TLS record out of order.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.unexpected_message
            }
         })
      };
      p.handleHelloRequest = function(e, t, a) {
         !e.handshaking && e.handshakes > 0 && (p.queue(e, p.createAlert(e, {
            level: p.Alert.Level.warning,
            description: p.Alert.Description.no_renegotiation
         })), p.flush(e)), e.process()
      };
      p.parseHelloMessage = function(e, t, a) {
         var r = null,
            n = e.entity === p.ConnectionEnd.client;
         if (a < 38) e.error(e, {
            message: n ? "Invalid ServerHello message. Message too short." : "Invalid ClientHello message. Message too short.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.illegal_parameter
            }
         });
         else {
            var i = t.fragment,
               s = i.length();
            if (r = {
                  version: {
                     major: i.getByte(),
                     minor: i.getByte()
                  },
                  random: N.util.createBuffer(i.getBytes(32)),
                  session_id: lt(i, 1),
                  extensions: []
               }, n ? (r.cipher_suite = i.getBytes(2), r.compression_method = i.getByte()) : (r.cipher_suites = lt(i, 2), r.compression_methods = lt(i, 1)), s = a - (s - i.length()), s > 0) {
               for (var o = lt(i, 2); o.length() > 0;) r.extensions.push({
                  type: [o.getByte(), o.getByte()],
                  data: lt(o, 2)
               });
               if (!n)
                  for (var u = 0; u < r.extensions.length; ++u) {
                     var l = r.extensions[u];
                     if (l.type[0] === 0 && l.type[1] === 0)
                        for (var c = lt(l.data, 2); c.length() > 0;) {
                           var f = c.getByte();
                           if (f !== 0) break;
                           e.session.extensions.server_name.serverNameList.push(lt(c, 2).getBytes())
                        }
                  }
            }
            if (e.session.version && (r.version.major !== e.session.version.major || r.version.minor !== e.session.version.minor)) return e.error(e, {
               message: "TLS version change is disallowed during renegotiation.",
               send: !0,
               alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.protocol_version
               }
            });
            if (n) e.session.cipherSuite = p.getCipherSuite(r.cipher_suite);
            else
               for (var y = N.util.createBuffer(r.cipher_suites.bytes()); y.length() > 0 && (e.session.cipherSuite = p.getCipherSuite(y.getBytes(2)), e.session.cipherSuite === null););
            if (e.session.cipherSuite === null) return e.error(e, {
               message: "No cipher suites in common.",
               send: !0,
               alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.handshake_failure
               },
               cipherSuite: N.util.bytesToHex(r.cipher_suite)
            });
            n ? e.session.compressionMethod = r.compression_method : e.session.compressionMethod = p.CompressionMethod.none
         }
         return r
      };
      p.createSecurityParameters = function(e, t) {
         var a = e.entity === p.ConnectionEnd.client,
            r = t.random.bytes(),
            n = a ? e.session.sp.client_random : r,
            i = a ? r : p.createRandom().getBytes();
         e.session.sp = {
            entity: e.entity,
            prf_algorithm: p.PRFAlgorithm.tls_prf_sha256,
            bulk_cipher_algorithm: null,
            cipher_type: null,
            enc_key_length: null,
            block_length: null,
            fixed_iv_length: null,
            record_iv_length: null,
            mac_algorithm: null,
            mac_length: null,
            mac_key_length: null,
            compression_algorithm: e.session.compressionMethod,
            pre_master_secret: null,
            master_secret: null,
            client_random: n,
            server_random: i
         }
      };
      p.handleServerHello = function(e, t, a) {
         var r = p.parseHelloMessage(e, t, a);
         if (!e.fail) {
            if (r.version.minor <= e.version.minor) e.version.minor = r.version.minor;
            else return e.error(e, {
               message: "Incompatible TLS version.",
               send: !0,
               alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.protocol_version
               }
            });
            e.session.version = e.version;
            var n = r.session_id.bytes();
            n.length > 0 && n === e.session.id ? (e.expect = Ml, e.session.resuming = !0, e.session.sp.server_random = r.random.bytes()) : (e.expect = lp, e.session.resuming = !1, p.createSecurityParameters(e, r)), e.session.id = n, e.process()
         }
      };
      p.handleClientHello = function(e, t, a) {
         var r = p.parseHelloMessage(e, t, a);
         if (!e.fail) {
            var n = r.session_id.bytes(),
               i = null;
            if (e.sessionCache && (i = e.sessionCache.getSession(n), i === null ? n = "" : (i.version.major !== r.version.major || i.version.minor > r.version.minor) && (i = null, n = "")), n.length === 0 && (n = N.random.getBytes(32)), e.session.id = n, e.session.clientHelloVersion = r.version, e.session.sp = {}, i) e.version = e.session.version = i.version, e.session.sp = i.sp;
            else {
               for (var s, o = 1; o < p.SupportedVersions.length && (s = p.SupportedVersions[o], !(s.minor <= r.version.minor)); ++o);
               e.version = {
                  major: s.major,
                  minor: s.minor
               }, e.session.version = e.version
            }
            i !== null ? (e.expect = Ls, e.session.resuming = !0, e.session.sp.client_random = r.random.bytes()) : (e.expect = e.verifyClient !== !1 ? mp : Rs, e.session.resuming = !1, p.createSecurityParameters(e, r)), e.open = !0, p.queue(e, p.createRecord(e, {
               type: p.ContentType.handshake,
               data: p.createServerHello(e)
            })), e.session.resuming ? (p.queue(e, p.createRecord(e, {
               type: p.ContentType.change_cipher_spec,
               data: p.createChangeCipherSpec()
            })), e.state.pending = p.createConnectionState(e), e.state.current.write = e.state.pending.write, p.queue(e, p.createRecord(e, {
               type: p.ContentType.handshake,
               data: p.createFinished(e)
            }))) : (p.queue(e, p.createRecord(e, {
               type: p.ContentType.handshake,
               data: p.createCertificate(e)
            })), e.fail || (p.queue(e, p.createRecord(e, {
               type: p.ContentType.handshake,
               data: p.createServerKeyExchange(e)
            })), e.verifyClient !== !1 && p.queue(e, p.createRecord(e, {
               type: p.ContentType.handshake,
               data: p.createCertificateRequest(e)
            })), p.queue(e, p.createRecord(e, {
               type: p.ContentType.handshake,
               data: p.createServerHelloDone(e)
            })))), p.flush(e), e.process()
         }
      };
      p.handleCertificate = function(e, t, a) {
         if (a < 3) return e.error(e, {
            message: "Invalid Certificate message. Message too short.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.illegal_parameter
            }
         });
         var r = t.fragment,
            n = {
               certificate_list: lt(r, 3)
            },
            i, s, o = [];
         try {
            for (; n.certificate_list.length() > 0;) i = lt(n.certificate_list, 3), s = N.asn1.fromDer(i), i = N.pki.certificateFromAsn1(s, !0), o.push(i)
         } catch (l) {
            return e.error(e, {
               message: "Could not parse certificate list.",
               cause: l,
               send: !0,
               alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.bad_certificate
               }
            })
         }
         var u = e.entity === p.ConnectionEnd.client;
         (u || e.verifyClient === !0) && o.length === 0 ? e.error(e, {
            message: u ? "No server certificate provided." : "No client certificate provided.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.illegal_parameter
            }
         }) : o.length === 0 ? e.expect = u ? Pl : Rs : (u ? e.session.serverCertificate = o[0] : e.session.clientCertificate = o[0], p.verifyCertificateChain(e, o) && (e.expect = u ? Pl : Rs)), e.process()
      };
      p.handleServerKeyExchange = function(e, t, a) {
         if (a > 0) return e.error(e, {
            message: "Invalid key parameters. Only RSA is supported.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.unsupported_certificate
            }
         });
         e.expect = cp, e.process()
      };
      p.handleClientKeyExchange = function(e, t, a) {
         if (a < 48) return e.error(e, {
            message: "Invalid key parameters. Only RSA is supported.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.unsupported_certificate
            }
         });
         var r = t.fragment,
            n = {
               enc_pre_master_secret: lt(r, 2).getBytes()
            },
            i = null;
         if (e.getPrivateKey) try {
            i = e.getPrivateKey(e, e.session.serverCertificate), i = N.pki.privateKeyFromPem(i)
         } catch (u) {
            e.error(e, {
               message: "Could not get private key.",
               cause: u,
               send: !0,
               alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.internal_error
               }
            })
         }
         if (i === null) return e.error(e, {
            message: "No private key set.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.internal_error
            }
         });
         try {
            var s = e.session.sp;
            s.pre_master_secret = i.decrypt(n.enc_pre_master_secret);
            var o = e.session.clientHelloVersion;
            if (o.major !== s.pre_master_secret.charCodeAt(0) || o.minor !== s.pre_master_secret.charCodeAt(1)) throw new Error("TLS version rollback attack detected.")
         } catch {
            s.pre_master_secret = N.random.getBytes(48)
         }
         e.expect = Ls, e.session.clientCertificate !== null && (e.expect = gp), e.process()
      };
      p.handleCertificateRequest = function(e, t, a) {
         if (a < 3) return e.error(e, {
            message: "Invalid CertificateRequest. Message too short.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.illegal_parameter
            }
         });
         var r = t.fragment,
            n = {
               certificate_types: lt(r, 1),
               certificate_authorities: lt(r, 2)
            };
         e.session.certificateRequest = n, e.expect = fp, e.process()
      };
      p.handleCertificateVerify = function(e, t, a) {
         if (a < 2) return e.error(e, {
            message: "Invalid CertificateVerify. Message too short.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.illegal_parameter
            }
         });
         var r = t.fragment;
         r.read -= 4;
         var n = r.bytes();
         r.read += 4;
         var i = {
               signature: lt(r, 2).getBytes()
            },
            s = N.util.createBuffer();
         s.putBuffer(e.session.md5.digest()), s.putBuffer(e.session.sha1.digest()), s = s.getBytes();
         try {
            var o = e.session.clientCertificate;
            if (!o.publicKey.verify(s, i.signature, "NONE")) throw new Error("CertificateVerify signature does not match.");
            e.session.md5.update(n), e.session.sha1.update(n)
         } catch {
            return e.error(e, {
               message: "Bad signature in CertificateVerify.",
               send: !0,
               alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.handshake_failure
               }
            })
         }
         e.expect = Ls, e.process()
      };
      p.handleServerHelloDone = function(e, t, a) {
         if (a > 0) return e.error(e, {
            message: "Invalid ServerHelloDone message. Invalid length.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.record_overflow
            }
         });
         if (e.serverCertificate === null) {
            var r = {
                  message: "No server certificate provided. Not enough security.",
                  send: !0,
                  alert: {
                     level: p.Alert.Level.fatal,
                     description: p.Alert.Description.insufficient_security
                  }
               },
               n = 0,
               i = e.verify(e, r.alert.description, n, []);
            if (i !== !0) return (i || i === 0) && (typeof i == "object" && !N.util.isArray(i) ? (i.message && (r.message = i.message), i.alert && (r.alert.description = i.alert)) : typeof i == "number" && (r.alert.description = i)), e.error(e, r)
         }
         e.session.certificateRequest !== null && (t = p.createRecord(e, {
            type: p.ContentType.handshake,
            data: p.createCertificate(e)
         }), p.queue(e, t)), t = p.createRecord(e, {
            type: p.ContentType.handshake,
            data: p.createClientKeyExchange(e)
         }), p.queue(e, t), e.expect = pp;
         var s = function(o, u) {
            o.session.certificateRequest !== null && o.session.clientCertificate !== null && p.queue(o, p.createRecord(o, {
               type: p.ContentType.handshake,
               data: p.createCertificateVerify(o, u)
            })), p.queue(o, p.createRecord(o, {
               type: p.ContentType.change_cipher_spec,
               data: p.createChangeCipherSpec()
            })), o.state.pending = p.createConnectionState(o), o.state.current.write = o.state.pending.write, p.queue(o, p.createRecord(o, {
               type: p.ContentType.handshake,
               data: p.createFinished(o)
            })), o.expect = Ml, p.flush(o), o.process()
         };
         if (e.session.certificateRequest === null || e.session.clientCertificate === null) return s(e, null);
         p.getClientSignature(e, s)
      };
      p.handleChangeCipherSpec = function(e, t) {
         if (t.fragment.getByte() !== 1) return e.error(e, {
            message: "Invalid ChangeCipherSpec message received.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.illegal_parameter
            }
         });
         var a = e.entity === p.ConnectionEnd.client;
         (e.session.resuming && a || !e.session.resuming && !a) && (e.state.pending = p.createConnectionState(e)), e.state.current.read = e.state.pending.read, (!e.session.resuming && a || e.session.resuming && !a) && (e.state.pending = null), e.expect = a ? hp : vp, e.process()
      };
      p.handleFinished = function(e, t, a) {
         var r = t.fragment;
         r.read -= 4;
         var n = r.bytes();
         r.read += 4;
         var i = t.fragment.getBytes();
         r = N.util.createBuffer(), r.putBuffer(e.session.md5.digest()), r.putBuffer(e.session.sha1.digest());
         var s = e.entity === p.ConnectionEnd.client,
            o = s ? "server finished" : "client finished",
            u = e.session.sp,
            l = 12,
            c = ii;
         if (r = c(u.master_secret, o, r.getBytes(), l), r.getBytes() !== i) return e.error(e, {
            message: "Invalid verify_data in Finished message.",
            send: !0,
            alert: {
               level: p.Alert.Level.fatal,
               description: p.Alert.Description.decrypt_error
            }
         });
         e.session.md5.update(n), e.session.sha1.update(n), (e.session.resuming && s || !e.session.resuming && !s) && (p.queue(e, p.createRecord(e, {
            type: p.ContentType.change_cipher_spec,
            data: p.createChangeCipherSpec()
         })), e.state.current.write = e.state.pending.write, e.state.pending = null, p.queue(e, p.createRecord(e, {
            type: p.ContentType.handshake,
            data: p.createFinished(e)
         }))), e.expect = s ? dp : Ep, e.handshaking = !1, ++e.handshakes, e.peerCertificate = s ? e.session.serverCertificate : e.session.clientCertificate, p.flush(e), e.isConnected = !0, e.connected(e), e.process()
      };
      p.handleAlert = function(e, t) {
         var a = t.fragment,
            r = {
               level: a.getByte(),
               description: a.getByte()
            },
            n;
         switch (r.description) {
            case p.Alert.Description.close_notify:
               n = "Connection closed.";
               break;
            case p.Alert.Description.unexpected_message:
               n = "Unexpected message.";
               break;
            case p.Alert.Description.bad_record_mac:
               n = "Bad record MAC.";
               break;
            case p.Alert.Description.decryption_failed:
               n = "Decryption failed.";
               break;
            case p.Alert.Description.record_overflow:
               n = "Record overflow.";
               break;
            case p.Alert.Description.decompression_failure:
               n = "Decompression failed.";
               break;
            case p.Alert.Description.handshake_failure:
               n = "Handshake failure.";
               break;
            case p.Alert.Description.bad_certificate:
               n = "Bad certificate.";
               break;
            case p.Alert.Description.unsupported_certificate:
               n = "Unsupported certificate.";
               break;
            case p.Alert.Description.certificate_revoked:
               n = "Certificate revoked.";
               break;
            case p.Alert.Description.certificate_expired:
               n = "Certificate expired.";
               break;
            case p.Alert.Description.certificate_unknown:
               n = "Certificate unknown.";
               break;
            case p.Alert.Description.illegal_parameter:
               n = "Illegal parameter.";
               break;
            case p.Alert.Description.unknown_ca:
               n = "Unknown certificate authority.";
               break;
            case p.Alert.Description.access_denied:
               n = "Access denied.";
               break;
            case p.Alert.Description.decode_error:
               n = "Decode error.";
               break;
            case p.Alert.Description.decrypt_error:
               n = "Decrypt error.";
               break;
            case p.Alert.Description.export_restriction:
               n = "Export restriction.";
               break;
            case p.Alert.Description.protocol_version:
               n = "Unsupported protocol version.";
               break;
            case p.Alert.Description.insufficient_security:
               n = "Insufficient security.";
               break;
            case p.Alert.Description.internal_error:
               n = "Internal error.";
               break;
            case p.Alert.Description.user_canceled:
               n = "User canceled.";
               break;
            case p.Alert.Description.no_renegotiation:
               n = "Renegotiation not supported.";
               break;
            default:
               n = "Unknown error.";
               break
         }
         if (r.description === p.Alert.Description.close_notify) return e.close();
         e.error(e, {
            message: n,
            send: !1,
            origin: e.entity === p.ConnectionEnd.client ? "server" : "client",
            alert: r
         }), e.process()
      };
      p.handleHandshake = function(e, t) {
         var a = t.fragment,
            r = a.getByte(),
            n = a.getInt24();
         if (n > a.length()) return e.fragmented = t, t.fragment = N.util.createBuffer(), a.read -= 4, e.process();
         e.fragmented = null, a.read -= 4;
         var i = a.bytes(n + 4);
         a.read += 4, r in ni[e.entity][e.expect] ? (e.entity === p.ConnectionEnd.server && !e.open && !e.fail && (e.handshaking = !0, e.session = {
            version: null,
            extensions: {
               server_name: {
                  serverNameList: []
               }
            },
            cipherSuite: null,
            compressionMethod: null,
            serverCertificate: null,
            clientCertificate: null,
            md5: N.md.md5.create(),
            sha1: N.md.sha1.create()
         }), r !== p.HandshakeType.hello_request && r !== p.HandshakeType.certificate_verify && r !== p.HandshakeType.finished && (e.session.md5.update(i), e.session.sha1.update(i)), ni[e.entity][e.expect][r](e, t, n)) : p.handleUnexpected(e, t)
      };
      p.handleApplicationData = function(e, t) {
         e.data.putBuffer(t.fragment), e.dataReady(e), e.process()
      };
      p.handleHeartbeat = function(e, t) {
         var a = t.fragment,
            r = a.getByte(),
            n = a.getInt16(),
            i = a.getBytes(n);
         if (r === p.HeartbeatMessageType.heartbeat_request) {
            if (e.handshaking || n > i.length) return e.process();
            p.queue(e, p.createRecord(e, {
               type: p.ContentType.heartbeat,
               data: p.createHeartbeat(p.HeartbeatMessageType.heartbeat_response, i)
            })), p.flush(e)
         } else if (r === p.HeartbeatMessageType.heartbeat_response) {
            if (i !== e.expectedHeartbeatPayload) return e.process();
            e.heartbeatReceived && e.heartbeatReceived(e, N.util.createBuffer(i))
         }
         e.process()
      };
      var up = 0,
         lp = 1,
         Pl = 2,
         cp = 3,
         fp = 4,
         Ml = 5,
         hp = 6,
         dp = 7,
         pp = 8,
         yp = 0,
         mp = 1,
         Rs = 2,
         gp = 3,
         Ls = 4,
         vp = 5,
         Ep = 6,
         d = p.handleUnexpected,
         Kl = p.handleChangeCipherSpec,
         Fe = p.handleAlert,
         at = p.handleHandshake,
         ql = p.handleApplicationData,
         Pe = p.handleHeartbeat,
         ks = [];
      ks[p.ConnectionEnd.client] = [
         [d, Fe, at, d, Pe],
         [d, Fe, at, d, Pe],
         [d, Fe, at, d, Pe],
         [d, Fe, at, d, Pe],
         [d, Fe, at, d, Pe],
         [Kl, Fe, d, d, Pe],
         [d, Fe, at, d, Pe],
         [d, Fe, at, ql, Pe],
         [d, Fe, at, d, Pe]
      ];
      ks[p.ConnectionEnd.server] = [
         [d, Fe, at, d, Pe],
         [d, Fe, at, d, Pe],
         [d, Fe, at, d, Pe],
         [d, Fe, at, d, Pe],
         [Kl, Fe, d, d, Pe],
         [d, Fe, at, d, Pe],
         [d, Fe, at, ql, Pe],
         [d, Fe, at, d, Pe]
      ];
      var hr = p.handleHelloRequest,
         Cp = p.handleServerHello,
         Hl = p.handleCertificate,
         Vl = p.handleServerKeyExchange,
         _s = p.handleCertificateRequest,
         ri = p.handleServerHelloDone,
         Gl = p.handleFinished,
         ni = [];
      ni[p.ConnectionEnd.client] = [
         [d, d, Cp, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d],
         [hr, d, d, d, d, d, d, d, d, d, d, Hl, Vl, _s, ri, d, d, d, d, d, d],
         [hr, d, d, d, d, d, d, d, d, d, d, d, Vl, _s, ri, d, d, d, d, d, d],
         [hr, d, d, d, d, d, d, d, d, d, d, d, d, _s, ri, d, d, d, d, d, d],
         [hr, d, d, d, d, d, d, d, d, d, d, d, d, d, ri, d, d, d, d, d, d],
         [hr, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d],
         [hr, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, Gl],
         [hr, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d],
         [hr, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d]
      ];
      var xp = p.handleClientHello,
         Tp = p.handleClientKeyExchange,
         Sp = p.handleCertificateVerify;
      ni[p.ConnectionEnd.server] = [
         [d, xp, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d],
         [d, d, d, d, d, d, d, d, d, d, d, Hl, d, d, d, d, d, d, d, d, d],
         [d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, Tp, d, d, d, d],
         [d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, Sp, d, d, d, d, d],
         [d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d],
         [d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, Gl],
         [d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d],
         [d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d]
      ];
      p.generateKeys = function(e, t) {
         var a = ii,
            r = t.client_random + t.server_random;
         e.session.resuming || (t.master_secret = a(t.pre_master_secret, "master secret", r, 48).bytes(), t.pre_master_secret = null), r = t.server_random + t.client_random;
         var n = 2 * t.mac_key_length + 2 * t.enc_key_length,
            i = e.version.major === p.Versions.TLS_1_0.major && e.version.minor === p.Versions.TLS_1_0.minor;
         i && (n += 2 * t.fixed_iv_length);
         var s = a(t.master_secret, "key expansion", r, n),
            o = {
               client_write_MAC_key: s.getBytes(t.mac_key_length),
               server_write_MAC_key: s.getBytes(t.mac_key_length),
               client_write_key: s.getBytes(t.enc_key_length),
               server_write_key: s.getBytes(t.enc_key_length)
            };
         return i && (o.client_write_IV = s.getBytes(t.fixed_iv_length), o.server_write_IV = s.getBytes(t.fixed_iv_length)), o
      };
      p.createConnectionState = function(e) {
         var t = e.entity === p.ConnectionEnd.client,
            a = function() {
               var i = {
                  sequenceNumber: [0, 0],
                  macKey: null,
                  macLength: 0,
                  macFunction: null,
                  cipherState: null,
                  cipherFunction: function(s) {
                     return !0
                  },
                  compressionState: null,
                  compressFunction: function(s) {
                     return !0
                  },
                  updateSequenceNumber: function() {
                     i.sequenceNumber[1] === 4294967295 ? (i.sequenceNumber[1] = 0, ++i.sequenceNumber[0]) : ++i.sequenceNumber[1]
                  }
               };
               return i
            },
            r = {
               read: a(),
               write: a()
            };
         if (r.read.update = function(i, s) {
               return r.read.cipherFunction(s, r.read) ? r.read.compressFunction(i, s, r.read) || i.error(i, {
                  message: "Could not decompress record.",
                  send: !0,
                  alert: {
                     level: p.Alert.Level.fatal,
                     description: p.Alert.Description.decompression_failure
                  }
               }) : i.error(i, {
                  message: "Could not decrypt record or bad MAC.",
                  send: !0,
                  alert: {
                     level: p.Alert.Level.fatal,
                     description: p.Alert.Description.bad_record_mac
                  }
               }), !i.fail
            }, r.write.update = function(i, s) {
               return r.write.compressFunction(i, s, r.write) ? r.write.cipherFunction(s, r.write) || i.error(i, {
                  message: "Could not encrypt record.",
                  send: !1,
                  alert: {
                     level: p.Alert.Level.fatal,
                     description: p.Alert.Description.internal_error
                  }
               }) : i.error(i, {
                  message: "Could not compress record.",
                  send: !1,
                  alert: {
                     level: p.Alert.Level.fatal,
                     description: p.Alert.Description.internal_error
                  }
               }), !i.fail
            }, e.session) {
            var n = e.session.sp;
            switch (e.session.cipherSuite.initSecurityParameters(n), n.keys = p.generateKeys(e, n), r.read.macKey = t ? n.keys.server_write_MAC_key : n.keys.client_write_MAC_key, r.write.macKey = t ? n.keys.client_write_MAC_key : n.keys.server_write_MAC_key, e.session.cipherSuite.initConnectionState(r, e, n), n.compression_algorithm) {
               case p.CompressionMethod.none:
                  break;
               case p.CompressionMethod.deflate:
                  r.read.compressFunction = op, r.write.compressFunction = sp;
                  break;
               default:
                  throw new Error("Unsupported compression algorithm.")
            }
         }
         return r
      };
      p.createRandom = function() {
         var e = new Date,
            t = +e + e.getTimezoneOffset() * 6e4,
            a = N.util.createBuffer();
         return a.putInt32(t), a.putBytes(N.random.getBytes(28)), a
      };
      p.createRecord = function(e, t) {
         if (!t.data) return null;
         var a = {
            type: t.type,
            version: {
               major: e.version.major,
               minor: e.version.minor
            },
            length: t.data.length(),
            fragment: t.data
         };
         return a
      };
      p.createAlert = function(e, t) {
         var a = N.util.createBuffer();
         return a.putByte(t.level), a.putByte(t.description), p.createRecord(e, {
            type: p.ContentType.alert,
            data: a
         })
      };
      p.createClientHello = function(e) {
         e.session.clientHelloVersion = {
            major: e.version.major,
            minor: e.version.minor
         };
         for (var t = N.util.createBuffer(), a = 0; a < e.cipherSuites.length; ++a) {
            var r = e.cipherSuites[a];
            t.putByte(r.id[0]), t.putByte(r.id[1])
         }
         var n = t.length(),
            i = N.util.createBuffer();
         i.putByte(p.CompressionMethod.none);
         var s = i.length(),
            o = N.util.createBuffer();
         if (e.virtualHost) {
            var u = N.util.createBuffer();
            u.putByte(0), u.putByte(0);
            var l = N.util.createBuffer();
            l.putByte(0), Ct(l, 2, N.util.createBuffer(e.virtualHost));
            var c = N.util.createBuffer();
            Ct(c, 2, l), Ct(u, 2, c), o.putBuffer(u)
         }
         var f = o.length();
         f > 0 && (f += 2);
         var y = e.session.id,
            g = y.length + 1 + 2 + 4 + 28 + 2 + n + 1 + s + f,
            m = N.util.createBuffer();
         return m.putByte(p.HandshakeType.client_hello), m.putInt24(g), m.putByte(e.version.major), m.putByte(e.version.minor), m.putBytes(e.session.sp.client_random), Ct(m, 1, N.util.createBuffer(y)), Ct(m, 2, t), Ct(m, 1, i), f > 0 && Ct(m, 2, o), m
      };
      p.createServerHello = function(e) {
         var t = e.session.id,
            a = t.length + 1 + 2 + 4 + 28 + 2 + 1,
            r = N.util.createBuffer();
         return r.putByte(p.HandshakeType.server_hello), r.putInt24(a), r.putByte(e.version.major), r.putByte(e.version.minor), r.putBytes(e.session.sp.server_random), Ct(r, 1, N.util.createBuffer(t)), r.putByte(e.session.cipherSuite.id[0]), r.putByte(e.session.cipherSuite.id[1]), r.putByte(e.session.compressionMethod), r
      };
      p.createCertificate = function(e) {
         var t = e.entity === p.ConnectionEnd.client,
            a = null;
         if (e.getCertificate) {
            var r;
            t ? r = e.session.certificateRequest : r = e.session.extensions.server_name.serverNameList, a = e.getCertificate(e, r)
         }
         var n = N.util.createBuffer();
         if (a !== null) try {
            N.util.isArray(a) || (a = [a]);
            for (var i = null, s = 0; s < a.length; ++s) {
               var o = N.pem.decode(a[s])[0];
               if (o.type !== "CERTIFICATE" && o.type !== "X509 CERTIFICATE" && o.type !== "TRUSTED CERTIFICATE") {
                  var u = new Error('Could not convert certificate from PEM; PEM header type is not "CERTIFICATE", "X509 CERTIFICATE", or "TRUSTED CERTIFICATE".');
                  throw u.headerType = o.type, u
               }
               if (o.procType && o.procType.type === "ENCRYPTED") throw new Error("Could not convert certificate from PEM; PEM is encrypted.");
               var l = N.util.createBuffer(o.body);
               i === null && (i = N.asn1.fromDer(l.bytes(), !1));
               var c = N.util.createBuffer();
               Ct(c, 3, l), n.putBuffer(c)
            }
            a = N.pki.certificateFromAsn1(i), t ? e.session.clientCertificate = a : e.session.serverCertificate = a
         } catch (g) {
            return e.error(e, {
               message: "Could not send certificate list.",
               cause: g,
               send: !0,
               alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.bad_certificate
               }
            })
         }
         var f = 3 + n.length(),
            y = N.util.createBuffer();
         return y.putByte(p.HandshakeType.certificate), y.putInt24(f), Ct(y, 3, n), y
      };
      p.createClientKeyExchange = function(e) {
         var t = N.util.createBuffer();
         t.putByte(e.session.clientHelloVersion.major), t.putByte(e.session.clientHelloVersion.minor), t.putBytes(N.random.getBytes(46));
         var a = e.session.sp;
         a.pre_master_secret = t.getBytes();
         var r = e.session.serverCertificate.publicKey;
         t = r.encrypt(a.pre_master_secret);
         var n = t.length + 2,
            i = N.util.createBuffer();
         return i.putByte(p.HandshakeType.client_key_exchange), i.putInt24(n), i.putInt16(t.length), i.putBytes(t), i
      };
      p.createServerKeyExchange = function(e) {
         var t = 0,
            a = N.util.createBuffer();
         return t > 0 && (a.putByte(p.HandshakeType.server_key_exchange), a.putInt24(t)), a
      };
      p.getClientSignature = function(e, t) {
         var a = N.util.createBuffer();
         a.putBuffer(e.session.md5.digest()), a.putBuffer(e.session.sha1.digest()), a = a.getBytes(), e.getSignature = e.getSignature || function(r, n, i) {
            var s = null;
            if (r.getPrivateKey) try {
               s = r.getPrivateKey(r, r.session.clientCertificate), s = N.pki.privateKeyFromPem(s)
            } catch (o) {
               r.error(r, {
                  message: "Could not get private key.",
                  cause: o,
                  send: !0,
                  alert: {
                     level: p.Alert.Level.fatal,
                     description: p.Alert.Description.internal_error
                  }
               })
            }
            s === null ? r.error(r, {
               message: "No private key set.",
               send: !0,
               alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.internal_error
               }
            }) : n = s.sign(n, null), i(r, n)
         }, e.getSignature(e, a, t)
      };
      p.createCertificateVerify = function(e, t) {
         var a = t.length + 2,
            r = N.util.createBuffer();
         return r.putByte(p.HandshakeType.certificate_verify), r.putInt24(a), r.putInt16(t.length), r.putBytes(t), r
      };
      p.createCertificateRequest = function(e) {
         var t = N.util.createBuffer();
         t.putByte(1);
         var a = N.util.createBuffer();
         for (var r in e.caStore.certs) {
            var n = e.caStore.certs[r],
               i = N.pki.distinguishedNameToAsn1(n.subject),
               s = N.asn1.toDer(i);
            a.putInt16(s.length()), a.putBuffer(s)
         }
         var o = 1 + t.length() + 2 + a.length(),
            u = N.util.createBuffer();
         return u.putByte(p.HandshakeType.certificate_request), u.putInt24(o), Ct(u, 1, t), Ct(u, 2, a), u
      };
      p.createServerHelloDone = function(e) {
         var t = N.util.createBuffer();
         return t.putByte(p.HandshakeType.server_hello_done), t.putInt24(0), t
      };
      p.createChangeCipherSpec = function() {
         var e = N.util.createBuffer();
         return e.putByte(1), e
      };
      p.createFinished = function(e) {
         var t = N.util.createBuffer();
         t.putBuffer(e.session.md5.digest()), t.putBuffer(e.session.sha1.digest());
         var a = e.entity === p.ConnectionEnd.client,
            r = e.session.sp,
            n = 12,
            i = ii,
            s = a ? "client finished" : "server finished";
         t = i(r.master_secret, s, t.getBytes(), n);
         var o = N.util.createBuffer();
         return o.putByte(p.HandshakeType.finished), o.putInt24(t.length()), o.putBuffer(t), o
      };
      p.createHeartbeat = function(e, t, a) {
         typeof a > "u" && (a = t.length);
         var r = N.util.createBuffer();
         r.putByte(e), r.putInt16(a), r.putBytes(t);
         var n = r.length(),
            i = Math.max(16, n - a - 3);
         return r.putBytes(N.random.getBytes(i)), r
      };
      p.queue = function(e, t) {
         if (t && !(t.fragment.length() === 0 && (t.type === p.ContentType.handshake || t.type === p.ContentType.alert || t.type === p.ContentType.change_cipher_spec))) {
            if (t.type === p.ContentType.handshake) {
               var a = t.fragment.bytes();
               e.session.md5.update(a), e.session.sha1.update(a), a = null
            }
            var r;
            if (t.fragment.length() <= p.MaxFragment) r = [t];
            else {
               r = [];
               for (var n = t.fragment.bytes(); n.length > p.MaxFragment;) r.push(p.createRecord(e, {
                  type: t.type,
                  data: N.util.createBuffer(n.slice(0, p.MaxFragment))
               })), n = n.slice(p.MaxFragment);
               n.length > 0 && r.push(p.createRecord(e, {
                  type: t.type,
                  data: N.util.createBuffer(n)
               }))
            }
            for (var i = 0; i < r.length && !e.fail; ++i) {
               var s = r[i],
                  o = e.state.current.write;
               o.update(e, s) && e.records.push(s)
            }
         }
      };
      p.flush = function(e) {
         for (var t = 0; t < e.records.length; ++t) {
            var a = e.records[t];
            e.tlsData.putByte(a.type), e.tlsData.putByte(a.version.major), e.tlsData.putByte(a.version.minor), e.tlsData.putInt16(a.fragment.length()), e.tlsData.putBuffer(e.records[t].fragment)
         }
         return e.records = [], e.tlsDataReady(e)
      };
      var Ds = function(e) {
            switch (e) {
               case !0:
                  return !0;
               case N.pki.certificateError.bad_certificate:
                  return p.Alert.Description.bad_certificate;
               case N.pki.certificateError.unsupported_certificate:
                  return p.Alert.Description.unsupported_certificate;
               case N.pki.certificateError.certificate_revoked:
                  return p.Alert.Description.certificate_revoked;
               case N.pki.certificateError.certificate_expired:
                  return p.Alert.Description.certificate_expired;
               case N.pki.certificateError.certificate_unknown:
                  return p.Alert.Description.certificate_unknown;
               case N.pki.certificateError.unknown_ca:
                  return p.Alert.Description.unknown_ca;
               default:
                  return p.Alert.Description.bad_certificate
            }
         },
         Ip = function(e) {
            switch (e) {
               case !0:
                  return !0;
               case p.Alert.Description.bad_certificate:
                  return N.pki.certificateError.bad_certificate;
               case p.Alert.Description.unsupported_certificate:
                  return N.pki.certificateError.unsupported_certificate;
               case p.Alert.Description.certificate_revoked:
                  return N.pki.certificateError.certificate_revoked;
               case p.Alert.Description.certificate_expired:
                  return N.pki.certificateError.certificate_expired;
               case p.Alert.Description.certificate_unknown:
                  return N.pki.certificateError.certificate_unknown;
               case p.Alert.Description.unknown_ca:
                  return N.pki.certificateError.unknown_ca;
               default:
                  return N.pki.certificateError.bad_certificate
            }
         };
      p.verifyCertificateChain = function(e, t) {
         try {
            var a = {};
            for (var r in e.verifyOptions) a[r] = e.verifyOptions[r];
            a.verify = function(i, s, o) {
               var u = Ds(i),
                  l = e.verify(e, i, s, o);
               if (l !== !0) {
                  if (typeof l == "object" && !N.util.isArray(l)) {
                     var c = new Error("The application rejected the certificate.");
                     throw c.send = !0, c.alert = {
                        level: p.Alert.Level.fatal,
                        description: p.Alert.Description.bad_certificate
                     }, l.message && (c.message = l.message), l.alert && (c.alert.description = l.alert), c
                  }
                  l !== i && (l = Ip(l))
               }
               return l
            }, N.pki.verifyCertificateChain(e.caStore, t, a)
         } catch (i) {
            var n = i;
            (typeof n != "object" || N.util.isArray(n)) && (n = {
               send: !0,
               alert: {
                  level: p.Alert.Level.fatal,
                  description: Ds(i)
               }
            }), "send" in n || (n.send = !0), "alert" in n || (n.alert = {
               level: p.Alert.Level.fatal,
               description: Ds(n.error)
            }), e.error(e, n)
         }
         return !e.fail
      };
      p.createSessionCache = function(e, t) {
         var a = null;
         if (e && e.getSession && e.setSession && e.order) a = e;
         else {
            a = {}, a.cache = e || {}, a.capacity = Math.max(t || 100, 1), a.order = [];
            for (var r in e) a.order.length <= t ? a.order.push(r) : delete e[r];
            a.getSession = function(n) {
               var i = null,
                  s = null;
               if (n ? s = N.util.bytesToHex(n) : a.order.length > 0 && (s = a.order[0]), s !== null && s in a.cache) {
                  i = a.cache[s], delete a.cache[s];
                  for (var o in a.order)
                     if (a.order[o] === s) {
                        a.order.splice(o, 1);
                        break
                     }
               }
               return i
            }, a.setSession = function(n, i) {
               if (a.order.length === a.capacity) {
                  var s = a.order.shift();
                  delete a.cache[s]
               }
               var s = N.util.bytesToHex(n);
               a.order.push(s), a.cache[s] = i
            }
         }
         return a
      };
      p.createConnection = function(e) {
         var t = null;
         e.caStore ? N.util.isArray(e.caStore) ? t = N.pki.createCaStore(e.caStore) : t = e.caStore : t = N.pki.createCaStore();
         var a = e.cipherSuites || null;
         if (a === null) {
            a = [];
            for (var r in p.CipherSuites) a.push(p.CipherSuites[r])
         }
         var n = e.server ? p.ConnectionEnd.server : p.ConnectionEnd.client,
            i = e.sessionCache ? p.createSessionCache(e.sessionCache) : null,
            s = {
               version: {
                  major: p.Version.major,
                  minor: p.Version.minor
               },
               entity: n,
               sessionId: e.sessionId,
               caStore: t,
               sessionCache: i,
               cipherSuites: a,
               connected: e.connected,
               virtualHost: e.virtualHost || null,
               verifyClient: e.verifyClient || !1,
               verify: e.verify || function(c, f, y, g) {
                  return f
               },
               verifyOptions: e.verifyOptions || {},
               getCertificate: e.getCertificate || null,
               getPrivateKey: e.getPrivateKey || null,
               getSignature: e.getSignature || null,
               input: N.util.createBuffer(),
               tlsData: N.util.createBuffer(),
               data: N.util.createBuffer(),
               tlsDataReady: e.tlsDataReady,
               dataReady: e.dataReady,
               heartbeatReceived: e.heartbeatReceived,
               closed: e.closed,
               error: function(c, f) {
                  f.origin = f.origin || (c.entity === p.ConnectionEnd.client ? "client" : "server"), f.send && (p.queue(c, p.createAlert(c, f.alert)), p.flush(c));
                  var y = f.fatal !== !1;
                  y && (c.fail = !0), e.error(c, f), y && c.close(!1)
               },
               deflate: e.deflate || null,
               inflate: e.inflate || null
            };
         s.reset = function(c) {
            s.version = {
               major: p.Version.major,
               minor: p.Version.minor
            }, s.record = null, s.session = null, s.peerCertificate = null, s.state = {
               pending: null,
               current: null
            }, s.expect = s.entity === p.ConnectionEnd.client ? up : yp, s.fragmented = null, s.records = [], s.open = !1, s.handshakes = 0, s.handshaking = !1, s.isConnected = !1, s.fail = !(c || typeof c > "u"), s.input.clear(), s.tlsData.clear(), s.data.clear(), s.state.current = p.createConnectionState(s)
         }, s.reset();
         var o = function(c, f) {
               var y = f.type - p.ContentType.change_cipher_spec,
                  g = ks[c.entity][c.expect];
               y in g ? g[y](c, f) : p.handleUnexpected(c, f)
            },
            u = function(c) {
               var f = 0,
                  y = c.input,
                  g = y.length();
               if (g < 5) f = 5 - g;
               else {
                  c.record = {
                     type: y.getByte(),
                     version: {
                        major: y.getByte(),
                        minor: y.getByte()
                     },
                     length: y.getInt16(),
                     fragment: N.util.createBuffer(),
                     ready: !1
                  };
                  var m = c.record.version.major === c.version.major;
                  m && c.session && c.session.version && (m = c.record.version.minor === c.version.minor), m || c.error(c, {
                     message: "Incompatible TLS version.",
                     send: !0,
                     alert: {
                        level: p.Alert.Level.fatal,
                        description: p.Alert.Description.protocol_version
                     }
                  })
               }
               return f
            },
            l = function(c) {
               var f = 0,
                  y = c.input,
                  g = y.length();
               if (g < c.record.length) f = c.record.length - g;
               else {
                  c.record.fragment.putBytes(y.getBytes(c.record.length)), y.compact();
                  var m = c.state.current.read;
                  m.update(c, c.record) && (c.fragmented !== null && (c.fragmented.type === c.record.type ? (c.fragmented.fragment.putBuffer(c.record.fragment), c.record = c.fragmented) : c.error(c, {
                     message: "Invalid fragmented record.",
                     send: !0,
                     alert: {
                        level: p.Alert.Level.fatal,
                        description: p.Alert.Description.unexpected_message
                     }
                  })), c.record.ready = !0)
               }
               return f
            };
         return s.handshake = function(c) {
            if (s.entity !== p.ConnectionEnd.client) s.error(s, {
               message: "Cannot initiate handshake as a server.",
               fatal: !1
            });
            else if (s.handshaking) s.error(s, {
               message: "Handshake already in progress.",
               fatal: !1
            });
            else {
               s.fail && !s.open && s.handshakes === 0 && (s.fail = !1), s.handshaking = !0, c = c || "";
               var f = null;
               c.length > 0 && (s.sessionCache && (f = s.sessionCache.getSession(c)), f === null && (c = "")), c.length === 0 && s.sessionCache && (f = s.sessionCache.getSession(), f !== null && (c = f.id)), s.session = {
                  id: c,
                  version: null,
                  cipherSuite: null,
                  compressionMethod: null,
                  serverCertificate: null,
                  certificateRequest: null,
                  clientCertificate: null,
                  sp: {},
                  md5: N.md.md5.create(),
                  sha1: N.md.sha1.create()
               }, f && (s.version = f.version, s.session.sp = f.sp), s.session.sp.client_random = p.createRandom().getBytes(), s.open = !0, p.queue(s, p.createRecord(s, {
                  type: p.ContentType.handshake,
                  data: p.createClientHello(s)
               })), p.flush(s)
            }
         }, s.process = function(c) {
            var f = 0;
            return c && s.input.putBytes(c), s.fail || (s.record !== null && s.record.ready && s.record.fragment.isEmpty() && (s.record = null), s.record === null && (f = u(s)), !s.fail && s.record !== null && !s.record.ready && (f = l(s)), !s.fail && s.record !== null && s.record.ready && o(s, s.record)), f
         }, s.prepare = function(c) {
            return p.queue(s, p.createRecord(s, {
               type: p.ContentType.application_data,
               data: N.util.createBuffer(c)
            })), p.flush(s)
         }, s.prepareHeartbeatRequest = function(c, f) {
            return c instanceof N.util.ByteBuffer && (c = c.bytes()), typeof f > "u" && (f = c.length), s.expectedHeartbeatPayload = c, p.queue(s, p.createRecord(s, {
               type: p.ContentType.heartbeat,
               data: p.createHeartbeat(p.HeartbeatMessageType.heartbeat_request, c, f)
            })), p.flush(s)
         }, s.close = function(c) {
            if (!s.fail && s.sessionCache && s.session) {
               var f = {
                  id: s.session.id,
                  version: s.session.version,
                  sp: s.session.sp
               };
               f.sp.keys = null, s.sessionCache.setSession(f.id, f)
            }
            s.open && (s.open = !1, s.input.clear(), (s.isConnected || s.handshaking) && (s.isConnected = s.handshaking = !1, p.queue(s, p.createAlert(s, {
               level: p.Alert.Level.warning,
               description: p.Alert.Description.close_notify
            })), p.flush(s)), s.closed(s)), s.reset(c)
         }, s
      };
      zl.exports = N.tls = N.tls || {};
      for (ai in p) typeof p[ai] != "function" && (N.tls[ai] = p[ai]);
      var ai;
      N.tls.prf_tls1 = ii;
      N.tls.hmac_sha1 = ip;
      N.tls.createSessionCache = p.createSessionCache;
      N.tls.createConnection = p.createConnection
   });
   var Zl = Y((Vg, Yl) => {
      "use strict";
      var dr = $();
      sr();
      Os();
      var xt = Yl.exports = dr.tls;
      xt.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA = {
         id: [0, 47],
         name: "TLS_RSA_WITH_AES_128_CBC_SHA",
         initSecurityParameters: function(e) {
            e.bulk_cipher_algorithm = xt.BulkCipherAlgorithm.aes, e.cipher_type = xt.CipherType.block, e.enc_key_length = 16, e.block_length = 16, e.fixed_iv_length = 16, e.record_iv_length = 16, e.mac_algorithm = xt.MACAlgorithm.hmac_sha1, e.mac_length = 20, e.mac_key_length = 20
         },
         initConnectionState: Wl
      };
      xt.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA = {
         id: [0, 53],
         name: "TLS_RSA_WITH_AES_256_CBC_SHA",
         initSecurityParameters: function(e) {
            e.bulk_cipher_algorithm = xt.BulkCipherAlgorithm.aes, e.cipher_type = xt.CipherType.block, e.enc_key_length = 32, e.block_length = 16, e.fixed_iv_length = 16, e.record_iv_length = 16, e.mac_algorithm = xt.MACAlgorithm.hmac_sha1, e.mac_length = 20, e.mac_key_length = 20
         },
         initConnectionState: Wl
      };

      function Wl(e, t, a) {
         var r = t.entity === dr.tls.ConnectionEnd.client;
         e.read.cipherState = {
            init: !1,
            cipher: dr.cipher.createDecipher("AES-CBC", r ? a.keys.server_write_key : a.keys.client_write_key),
            iv: r ? a.keys.server_write_IV : a.keys.client_write_IV
         }, e.write.cipherState = {
            init: !1,
            cipher: dr.cipher.createCipher("AES-CBC", r ? a.keys.client_write_key : a.keys.server_write_key),
            iv: r ? a.keys.client_write_IV : a.keys.server_write_IV
         }, e.read.cipherFunction = wp, e.write.cipherFunction = bp, e.read.macLength = e.write.macLength = a.mac_length, e.read.macFunction = e.write.macFunction = xt.hmac_sha1
      }

      function bp(e, t) {
         var a = !1,
            r = t.macFunction(t.macKey, t.sequenceNumber, e);
         e.fragment.putBytes(r), t.updateSequenceNumber();
         var n;
         e.version.minor === xt.Versions.TLS_1_0.minor ? n = t.cipherState.init ? null : t.cipherState.iv : n = dr.random.getBytesSync(16), t.cipherState.init = !0;
         var i = t.cipherState.cipher;
         return i.start({
            iv: n
         }), e.version.minor >= xt.Versions.TLS_1_1.minor && i.output.putBytes(n), i.update(e.fragment), i.finish(Ap) && (e.fragment = i.output, e.length = e.fragment.length(), a = !0), a
      }

      function Ap(e, t, a) {
         if (!a) {
            var r = e - t.length() % e;
            t.fillWithByte(r - 1, r)
         }
         return !0
      }

      function Bp(e, t, a) {
         var r = !0;
         if (a) {
            for (var n = t.length(), i = t.last(), s = n - 1 - i; s < n - 1; ++s) r = r && t.at(s) == i;
            r && t.truncate(i + 1)
         }
         return r
      }

      function wp(e, t) {
         var a = !1,
            r;
         e.version.minor === xt.Versions.TLS_1_0.minor ? r = t.cipherState.init ? null : t.cipherState.iv : r = e.fragment.getBytes(16), t.cipherState.init = !0;
         var n = t.cipherState.cipher;
         n.start({
            iv: r
         }), n.update(e.fragment), a = n.finish(Bp);
         var i = t.macLength,
            s = dr.random.getBytesSync(i),
            o = n.output.length();
         o >= i ? (e.fragment = n.output.getBytes(o - i), s = n.output.getBytes(i)) : e.fragment = n.output.getBytes(), e.fragment = dr.util.createBuffer(e.fragment), e.length = e.fragment.length();
         var u = t.macFunction(t.macKey, t.sequenceNumber, e);
         return t.updateSequenceNumber(), a = Np(t.macKey, s, u) && a, a
      }

      function Np(e, t, a) {
         var r = dr.hmac.create();
         return r.start("SHA1", e), r.update(t), t = r.digest().getBytes(), r.start(null, null), r.update(a), a = r.digest().getBytes(), t === a
      }
   });
   var Ps = Y((Mg, Xl) => {
      "use strict";
      var Ee = $();
      Rt();
      ae();
      var sn = Xl.exports = Ee.sha512 = Ee.sha512 || {};
      Ee.md.sha512 = Ee.md.algorithms.sha512 = sn;
      var $l = Ee.sha384 = Ee.sha512.sha384 = Ee.sha512.sha384 || {};
      $l.create = function() {
         return sn.create("SHA-384")
      };
      Ee.md.sha384 = Ee.md.algorithms.sha384 = $l;
      Ee.sha512.sha256 = Ee.sha512.sha256 || {
         create: function() {
            return sn.create("SHA-512/256")
         }
      };
      Ee.md["sha512/256"] = Ee.md.algorithms["sha512/256"] = Ee.sha512.sha256;
      Ee.sha512.sha224 = Ee.sha512.sha224 || {
         create: function() {
            return sn.create("SHA-512/224")
         }
      };
      Ee.md["sha512/224"] = Ee.md.algorithms["sha512/224"] = Ee.sha512.sha224;
      sn.create = function(e) {
         if (jl || _p(), typeof e > "u" && (e = "SHA-512"), !(e in Nr)) throw new Error("Invalid SHA-512 algorithm: " + e);
         for (var t = Nr[e], a = null, r = Ee.util.createBuffer(), n = new Array(80), i = 0; i < 80; ++i) n[i] = new Array(2);
         var s = 64;
         switch (e) {
            case "SHA-384":
               s = 48;
               break;
            case "SHA-512/256":
               s = 32;
               break;
            case "SHA-512/224":
               s = 28;
               break
         }
         var o = {
            algorithm: e.replace("-", "").toLowerCase(),
            blockLength: 128,
            digestLength: s,
            messageLength: 0,
            fullMessageLength: null,
            messageLengthSize: 16
         };
         return o.start = function() {
            o.messageLength = 0, o.fullMessageLength = o.messageLength128 = [];
            for (var u = o.messageLengthSize / 4, l = 0; l < u; ++l) o.fullMessageLength.push(0);
            r = Ee.util.createBuffer(), a = new Array(t.length);
            for (var l = 0; l < t.length; ++l) a[l] = t[l].slice(0);
            return o
         }, o.start(), o.update = function(u, l) {
            l === "utf8" && (u = Ee.util.encodeUtf8(u));
            var c = u.length;
            o.messageLength += c, c = [c / 4294967296 >>> 0, c >>> 0];
            for (var f = o.fullMessageLength.length - 1; f >= 0; --f) o.fullMessageLength[f] += c[1], c[1] = c[0] + (o.fullMessageLength[f] / 4294967296 >>> 0), o.fullMessageLength[f] = o.fullMessageLength[f] >>> 0, c[0] = c[1] / 4294967296 >>> 0;
            return r.putBytes(u), Ql(a, n, r), (r.read > 2048 || r.length() === 0) && r.compact(), o
         }, o.digest = function() {
            var u = Ee.util.createBuffer();
            u.putBytes(r.bytes());
            var l = o.fullMessageLength[o.fullMessageLength.length - 1] + o.messageLengthSize,
               c = l & o.blockLength - 1;
            u.putBytes(Us.substr(0, o.blockLength - c));
            for (var f, y, g = o.fullMessageLength[0] * 8, m = 0; m < o.fullMessageLength.length - 1; ++m) f = o.fullMessageLength[m + 1] * 8, y = f / 4294967296 >>> 0, g += y, u.putInt32(g >>> 0), g = f >>> 0;
            u.putInt32(g);
            for (var x = new Array(a.length), m = 0; m < a.length; ++m) x[m] = a[m].slice(0);
            Ql(x, n, u);
            var T = Ee.util.createBuffer(),
               I;
            e === "SHA-512" ? I = x.length : e === "SHA-384" ? I = x.length - 2 : I = x.length - 4;
            for (var m = 0; m < I; ++m) T.putInt32(x[m][0]), (m !== I - 1 || e !== "SHA-512/224") && T.putInt32(x[m][1]);
            return T
         }, o
      };
      var Us = null,
         jl = !1,
         Fs = null,
         Nr = null;

      function _p() {
         Us = String.fromCharCode(128), Us += Ee.util.fillString(String.fromCharCode(0), 128), Fs = [
            [1116352408, 3609767458],
            [1899447441, 602891725],
            [3049323471, 3964484399],
            [3921009573, 2173295548],
            [961987163, 4081628472],
            [1508970993, 3053834265],
            [2453635748, 2937671579],
            [2870763221, 3664609560],
            [3624381080, 2734883394],
            [310598401, 1164996542],
            [607225278, 1323610764],
            [1426881987, 3590304994],
            [1925078388, 4068182383],
            [2162078206, 991336113],
            [2614888103, 633803317],
            [3248222580, 3479774868],
            [3835390401, 2666613458],
            [4022224774, 944711139],
            [264347078, 2341262773],
            [604807628, 2007800933],
            [770255983, 1495990901],
            [1249150122, 1856431235],
            [1555081692, 3175218132],
            [1996064986, 2198950837],
            [2554220882, 3999719339],
            [2821834349, 766784016],
            [2952996808, 2566594879],
            [3210313671, 3203337956],
            [3336571891, 1034457026],
            [3584528711, 2466948901],
            [113926993, 3758326383],
            [338241895, 168717936],
            [666307205, 1188179964],
            [773529912, 1546045734],
            [1294757372, 1522805485],
            [1396182291, 2643833823],
            [1695183700, 2343527390],
            [1986661051, 1014477480],
            [2177026350, 1206759142],
            [2456956037, 344077627],
            [2730485921, 1290863460],
            [2820302411, 3158454273],
            [3259730800, 3505952657],
            [3345764771, 106217008],
            [3516065817, 3606008344],
            [3600352804, 1432725776],
            [4094571909, 1467031594],
            [275423344, 851169720],
            [430227734, 3100823752],
            [506948616, 1363258195],
            [659060556, 3750685593],
            [883997877, 3785050280],
            [958139571, 3318307427],
            [1322822218, 3812723403],
            [1537002063, 2003034995],
            [1747873779, 3602036899],
            [1955562222, 1575990012],
            [2024104815, 1125592928],
            [2227730452, 2716904306],
            [2361852424, 442776044],
            [2428436474, 593698344],
            [2756734187, 3733110249],
            [3204031479, 2999351573],
            [3329325298, 3815920427],
            [3391569614, 3928383900],
            [3515267271, 566280711],
            [3940187606, 3454069534],
            [4118630271, 4000239992],
            [116418474, 1914138554],
            [174292421, 2731055270],
            [289380356, 3203993006],
            [460393269, 320620315],
            [685471733, 587496836],
            [852142971, 1086792851],
            [1017036298, 365543100],
            [1126000580, 2618297676],
            [1288033470, 3409855158],
            [1501505948, 4234509866],
            [1607167915, 987167468],
            [1816402316, 1246189591]
         ], Nr = {}, Nr["SHA-512"] = [
            [1779033703, 4089235720],
            [3144134277, 2227873595],
            [1013904242, 4271175723],
            [2773480762, 1595750129],
            [1359893119, 2917565137],
            [2600822924, 725511199],
            [528734635, 4215389547],
            [1541459225, 327033209]
         ], Nr["SHA-384"] = [
            [3418070365, 3238371032],
            [1654270250, 914150663],
            [2438529370, 812702999],
            [355462360, 4144912697],
            [1731405415, 4290775857],
            [2394180231, 1750603025],
            [3675008525, 1694076839],
            [1203062813, 3204075428]
         ], Nr["SHA-512/256"] = [
            [573645204, 4230739756],
            [2673172387, 3360449730],
            [596883563, 1867755857],
            [2520282905, 1497426621],
            [2519219938, 2827943907],
            [3193839141, 1401305490],
            [721525244, 746961066],
            [246885852, 2177182882]
         ], Nr["SHA-512/224"] = [
            [2352822216, 424955298],
            [1944164710, 2312950998],
            [502970286, 855612546],
            [1738396948, 1479516111],
            [258812777, 2077511080],
            [2011393907, 79989058],
            [1067287976, 1780299464],
            [286451373, 2446758561]
         ], jl = !0
      }

      function Ql(e, t, a) {
         for (var r, n, i, s, o, u, l, c, f, y, g, m, x, T, I, A, B, F, R, D, G, z, oe, ce, pe, ge, et, ht, fe, Ie, M, gr, Ur, be, Ae, we = a.length(); we >= 128;) {
            for (fe = 0; fe < 16; ++fe) t[fe][0] = a.getInt32() >>> 0, t[fe][1] = a.getInt32() >>> 0;
            for (; fe < 80; ++fe) gr = t[fe - 2], Ie = gr[0], M = gr[1], r = ((Ie >>> 19 | M << 13) ^ (M >>> 29 | Ie << 3) ^ Ie >>> 6) >>> 0, n = ((Ie << 13 | M >>> 19) ^ (M << 3 | Ie >>> 29) ^ (Ie << 26 | M >>> 6)) >>> 0, be = t[fe - 15], Ie = be[0], M = be[1], i = ((Ie >>> 1 | M << 31) ^ (Ie >>> 8 | M << 24) ^ Ie >>> 7) >>> 0, s = ((Ie << 31 | M >>> 1) ^ (Ie << 24 | M >>> 8) ^ (Ie << 25 | M >>> 7)) >>> 0, Ur = t[fe - 7], Ae = t[fe - 16], M = n + Ur[1] + s + Ae[1], t[fe][0] = r + Ur[0] + i + Ae[0] + (M / 4294967296 >>> 0) >>> 0, t[fe][1] = M >>> 0;
            for (x = e[0][0], T = e[0][1], I = e[1][0], A = e[1][1], B = e[2][0], F = e[2][1], R = e[3][0], D = e[3][1], G = e[4][0], z = e[4][1], oe = e[5][0], ce = e[5][1], pe = e[6][0], ge = e[6][1], et = e[7][0], ht = e[7][1], fe = 0; fe < 80; ++fe) l = ((G >>> 14 | z << 18) ^ (G >>> 18 | z << 14) ^ (z >>> 9 | G << 23)) >>> 0, c = ((G << 18 | z >>> 14) ^ (G << 14 | z >>> 18) ^ (z << 23 | G >>> 9)) >>> 0, f = (pe ^ G & (oe ^ pe)) >>> 0, y = (ge ^ z & (ce ^ ge)) >>> 0, o = ((x >>> 28 | T << 4) ^ (T >>> 2 | x << 30) ^ (T >>> 7 | x << 25)) >>> 0, u = ((x << 4 | T >>> 28) ^ (T << 30 | x >>> 2) ^ (T << 25 | x >>> 7)) >>> 0, g = (x & I | B & (x ^ I)) >>> 0, m = (T & A | F & (T ^ A)) >>> 0, M = ht + c + y + Fs[fe][1] + t[fe][1], r = et + l + f + Fs[fe][0] + t[fe][0] + (M / 4294967296 >>> 0) >>> 0, n = M >>> 0, M = u + m, i = o + g + (M / 4294967296 >>> 0) >>> 0, s = M >>> 0, et = pe, ht = ge, pe = oe, ge = ce, oe = G, ce = z, M = D + n, G = R + r + (M / 4294967296 >>> 0) >>> 0, z = M >>> 0, R = B, D = F, B = I, F = A, I = x, A = T, M = n + s, x = r + i + (M / 4294967296 >>> 0) >>> 0, T = M >>> 0;
            M = e[0][1] + T, e[0][0] = e[0][0] + x + (M / 4294967296 >>> 0) >>> 0, e[0][1] = M >>> 0, M = e[1][1] + A, e[1][0] = e[1][0] + I + (M / 4294967296 >>> 0) >>> 0, e[1][1] = M >>> 0, M = e[2][1] + F, e[2][0] = e[2][0] + B + (M / 4294967296 >>> 0) >>> 0, e[2][1] = M >>> 0, M = e[3][1] + D, e[3][0] = e[3][0] + R + (M / 4294967296 >>> 0) >>> 0, e[3][1] = M >>> 0, M = e[4][1] + z, e[4][0] = e[4][0] + G + (M / 4294967296 >>> 0) >>> 0, e[4][1] = M >>> 0, M = e[5][1] + ce, e[5][0] = e[5][0] + oe + (M / 4294967296 >>> 0) >>> 0, e[5][1] = M >>> 0, M = e[6][1] + ge, e[6][0] = e[6][0] + pe + (M / 4294967296 >>> 0) >>> 0, e[6][1] = M >>> 0, M = e[7][1] + ht, e[7][0] = e[7][0] + et + (M / 4294967296 >>> 0) >>> 0, e[7][1] = M >>> 0, we -= 128
         }
      }
   });
   var Jl = Y(Vs => {
      "use strict";
      var Dp = $();
      wt();
      var Ue = Dp.asn1;
      Vs.privateKeyValidator = {
         name: "PrivateKeyInfo",
         tagClass: Ue.Class.UNIVERSAL,
         type: Ue.Type.SEQUENCE,
         constructed: !0,
         value: [{
            name: "PrivateKeyInfo.version",
            tagClass: Ue.Class.UNIVERSAL,
            type: Ue.Type.INTEGER,
            constructed: !1,
            capture: "privateKeyVersion"
         }, {
            name: "PrivateKeyInfo.privateKeyAlgorithm",
            tagClass: Ue.Class.UNIVERSAL,
            type: Ue.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "AlgorithmIdentifier.algorithm",
               tagClass: Ue.Class.UNIVERSAL,
               type: Ue.Type.OID,
               constructed: !1,
               capture: "privateKeyOid"
            }]
         }, {
            name: "PrivateKeyInfo",
            tagClass: Ue.Class.UNIVERSAL,
            type: Ue.Type.OCTETSTRING,
            constructed: !1,
            capture: "privateKey"
         }]
      };
      Vs.publicKeyValidator = {
         name: "SubjectPublicKeyInfo",
         tagClass: Ue.Class.UNIVERSAL,
         type: Ue.Type.SEQUENCE,
         constructed: !0,
         captureAsn1: "subjectPublicKeyInfo",
         value: [{
            name: "SubjectPublicKeyInfo.AlgorithmIdentifier",
            tagClass: Ue.Class.UNIVERSAL,
            type: Ue.Type.SEQUENCE,
            constructed: !0,
            value: [{
               name: "AlgorithmIdentifier.algorithm",
               tagClass: Ue.Class.UNIVERSAL,
               type: Ue.Type.OID,
               constructed: !1,
               capture: "publicKeyOid"
            }]
         }, {
            tagClass: Ue.Class.UNIVERSAL,
            type: Ue.Type.BITSTRING,
            constructed: !1,
            composed: !0,
            captureBitStringValue: "ed25519PublicKey"
         }]
      }
   });
   var hc = Y((qg, fc) => {
      "use strict";
      var Ve = $();
      tn();
      mt();
      Ps();
      ae();
      var ic = Jl(),
         Rp = ic.publicKeyValidator,
         Lp = ic.privateKeyValidator;
      typeof ec > "u" && (ec = Ve.jsbn.BigInteger);
      var ec, qs = Ve.util.ByteBuffer,
         ot = typeof Buffer > "u" ? Uint8Array : Buffer;
      Ve.pki = Ve.pki || {};
      fc.exports = Ve.pki.ed25519 = Ve.ed25519 = Ve.ed25519 || {};
      var J = Ve.ed25519;
      J.constants = {};
      J.constants.PUBLIC_KEY_BYTE_LENGTH = 32;
      J.constants.PRIVATE_KEY_BYTE_LENGTH = 64;
      J.constants.SEED_BYTE_LENGTH = 32;
      J.constants.SIGN_BYTE_LENGTH = 64;
      J.constants.HASH_BYTE_LENGTH = 64;
      J.generateKeyPair = function(e) {
         e = e || {};
         var t = e.seed;
         if (t === void 0) t = Ve.random.getBytesSync(J.constants.SEED_BYTE_LENGTH);
         else if (typeof t == "string") {
            if (t.length !== J.constants.SEED_BYTE_LENGTH) throw new TypeError('"seed" must be ' + J.constants.SEED_BYTE_LENGTH + " bytes in length.")
         } else if (!(t instanceof Uint8Array)) throw new TypeError('"seed" must be a node.js Buffer, Uint8Array, or a binary string.');
         t = $t({
            message: t,
            encoding: "binary"
         });
         for (var a = new ot(J.constants.PUBLIC_KEY_BYTE_LENGTH), r = new ot(J.constants.PRIVATE_KEY_BYTE_LENGTH), n = 0; n < 32; ++n) r[n] = t[n];
         return Fp(a, r), {
            publicKey: a,
            privateKey: r
         }
      };
      J.privateKeyFromAsn1 = function(e) {
         var t = {},
            a = [],
            r = Ve.asn1.validate(e, Lp, t, a);
         if (!r) {
            var n = new Error("Invalid Key.");
            throw n.errors = a, n
         }
         var i = Ve.asn1.derToOid(t.privateKeyOid),
            s = Ve.oids.EdDSA25519;
         if (i !== s) throw new Error('Invalid OID "' + i + '"; OID must be "' + s + '".');
         var o = t.privateKey,
            u = $t({
               message: Ve.asn1.fromDer(o).value,
               encoding: "binary"
            });
         return {
            privateKeyBytes: u
         }
      };
      J.publicKeyFromAsn1 = function(e) {
         var t = {},
            a = [],
            r = Ve.asn1.validate(e, Rp, t, a);
         if (!r) {
            var n = new Error("Invalid Key.");
            throw n.errors = a, n
         }
         var i = Ve.asn1.derToOid(t.publicKeyOid),
            s = Ve.oids.EdDSA25519;
         if (i !== s) throw new Error('Invalid OID "' + i + '"; OID must be "' + s + '".');
         var o = t.ed25519PublicKey;
         if (o.length !== J.constants.PUBLIC_KEY_BYTE_LENGTH) throw new Error("Key length is invalid.");
         return $t({
            message: o,
            encoding: "binary"
         })
      };
      J.publicKeyFromPrivateKey = function(e) {
         e = e || {};
         var t = $t({
            message: e.privateKey,
            encoding: "binary"
         });
         if (t.length !== J.constants.PRIVATE_KEY_BYTE_LENGTH) throw new TypeError('"options.privateKey" must have a byte length of ' + J.constants.PRIVATE_KEY_BYTE_LENGTH);
         for (var a = new ot(J.constants.PUBLIC_KEY_BYTE_LENGTH), r = 0; r < a.length; ++r) a[r] = t[32 + r];
         return a
      };
      J.sign = function(e) {
         e = e || {};
         var t = $t(e),
            a = $t({
               message: e.privateKey,
               encoding: "binary"
            });
         if (a.length === J.constants.SEED_BYTE_LENGTH) {
            var r = J.generateKeyPair({
               seed: a
            });
            a = r.privateKey
         } else if (a.length !== J.constants.PRIVATE_KEY_BYTE_LENGTH) throw new TypeError('"options.privateKey" must have a byte length of ' + J.constants.SEED_BYTE_LENGTH + " or " + J.constants.PRIVATE_KEY_BYTE_LENGTH);
         var n = new ot(J.constants.SIGN_BYTE_LENGTH + t.length);
         Pp(n, t, t.length, a);
         for (var i = new ot(J.constants.SIGN_BYTE_LENGTH), s = 0; s < i.length; ++s) i[s] = n[s];
         return i
      };
      J.verify = function(e) {
         e = e || {};
         var t = $t(e);
         if (e.signature === void 0) throw new TypeError('"options.signature" must be a node.js Buffer, a Uint8Array, a forge ByteBuffer, or a binary string.');
         var a = $t({
            message: e.signature,
            encoding: "binary"
         });
         if (a.length !== J.constants.SIGN_BYTE_LENGTH) throw new TypeError('"options.signature" must have a byte length of ' + J.constants.SIGN_BYTE_LENGTH);
         var r = $t({
            message: e.publicKey,
            encoding: "binary"
         });
         if (r.length !== J.constants.PUBLIC_KEY_BYTE_LENGTH) throw new TypeError('"options.publicKey" must have a byte length of ' + J.constants.PUBLIC_KEY_BYTE_LENGTH);
         var n = new ot(J.constants.SIGN_BYTE_LENGTH + t.length),
            i = new ot(J.constants.SIGN_BYTE_LENGTH + t.length),
            s;
         for (s = 0; s < J.constants.SIGN_BYTE_LENGTH; ++s) n[s] = a[s];
         for (s = 0; s < t.length; ++s) n[s + J.constants.SIGN_BYTE_LENGTH] = t[s];
         return Vp(i, n, n.length, r) >= 0
      };

      function $t(e) {
         var t = e.message;
         if (t instanceof Uint8Array || t instanceof ot) return t;
         var a = e.encoding;
         if (t === void 0)
            if (e.md) t = e.md.digest().getBytes(), a = "binary";
            else throw new TypeError('"options.message" or "options.md" not specified.');
         if (typeof t == "string" && !a) throw new TypeError('"options.encoding" must be "binary" or "utf8".');
         if (typeof t == "string") {
            if (typeof Buffer < "u") return Buffer.from(t, a);
            t = new qs(t, a)
         } else if (!(t instanceof qs)) throw new TypeError('"options.message" must be a node.js Buffer, a Uint8Array, a forge ByteBuffer, or a string with "options.encoding" specifying its encoding.');
         for (var r = new ot(t.length()), n = 0; n < r.length; ++n) r[n] = t.at(n);
         return r
      }
      var Hs = H(),
         si = H([1]),
         kp = H([30883, 4953, 19914, 30187, 55467, 16705, 2637, 112, 59544, 30585, 16505, 36039, 65139, 11119, 27886, 20995]),
         Op = H([61785, 9906, 39828, 60374, 45398, 33411, 5274, 224, 53552, 61171, 33010, 6542, 64743, 22239, 55772, 9222]),
         tc = H([54554, 36645, 11616, 51542, 42930, 38181, 51040, 26924, 56412, 64982, 57905, 49316, 21502, 52590, 14035, 8553]),
         rc = H([26200, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214]),
         Ms = new Float64Array([237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16]),
         Up = H([41136, 18958, 6951, 50414, 58488, 44335, 6150, 12099, 55207, 15867, 153, 11085, 57099, 20417, 9344, 11139]);

      function on(e, t) {
         var a = Ve.md.sha512.create(),
            r = new qs(e);
         a.update(r.getBytes(t), "binary");
         var n = a.digest().getBytes();
         if (typeof Buffer < "u") return Buffer.from(n, "binary");
         for (var i = new ot(J.constants.HASH_BYTE_LENGTH), s = 0; s < 64; ++s) i[s] = n.charCodeAt(s);
         return i
      }

      function Fp(e, t) {
         var a = [H(), H(), H(), H()],
            r, n = on(t, 32);
         for (n[0] &= 248, n[31] &= 127, n[31] |= 64, Ys(a, n), Ws(e, a), r = 0; r < 32; ++r) t[r + 32] = e[r];
         return 0
      }

      function Pp(e, t, a, r) {
         var n, i, s = new Float64Array(64),
            o = [H(), H(), H(), H()],
            u = on(r, 32);
         u[0] &= 248, u[31] &= 127, u[31] |= 64;
         var l = a + 64;
         for (n = 0; n < a; ++n) e[64 + n] = t[n];
         for (n = 0; n < 32; ++n) e[32 + n] = u[32 + n];
         var c = on(e.subarray(32), a + 32);
         for (Gs(c), Ys(o, c), Ws(e, o), n = 32; n < 64; ++n) e[n] = r[n];
         var f = on(e, a + 64);
         for (Gs(f), n = 32; n < 64; ++n) s[n] = 0;
         for (n = 0; n < 32; ++n) s[n] = c[n];
         for (n = 0; n < 32; ++n)
            for (i = 0; i < 32; i++) s[n + i] += f[n] * u[i];
         return sc(e.subarray(32), s), l
      }

      function Vp(e, t, a, r) {
         var n, i, s = new ot(32),
            o = [H(), H(), H(), H()],
            u = [H(), H(), H(), H()];
         if (i = -1, a < 64 || Mp(u, r)) return -1;
         for (n = 0; n < a; ++n) e[n] = t[n];
         for (n = 0; n < 32; ++n) e[n + 32] = r[n];
         var l = on(e, a);
         if (Gs(l), lc(o, u, l), Ys(u, t.subarray(32)), zs(o, u), Ws(s, o), a -= 64, oc(t, 0, s, 0)) {
            for (n = 0; n < a; ++n) e[n] = 0;
            return -1
         }
         for (n = 0; n < a; ++n) e[n] = t[n + 64];
         return i = a, i
      }

      function sc(e, t) {
         var a, r, n, i;
         for (r = 63; r >= 32; --r) {
            for (a = 0, n = r - 32, i = r - 12; n < i; ++n) t[n] += a - 16 * t[r] * Ms[n - (r - 32)], a = t[n] + 128 >> 8, t[n] -= a * 256;
            t[n] += a, t[r] = 0
         }
         for (a = 0, n = 0; n < 32; ++n) t[n] += a - (t[31] >> 4) * Ms[n], a = t[n] >> 8, t[n] &= 255;
         for (n = 0; n < 32; ++n) t[n] -= a * Ms[n];
         for (r = 0; r < 32; ++r) t[r + 1] += t[r] >> 8, e[r] = t[r] & 255
      }

      function Gs(e) {
         for (var t = new Float64Array(64), a = 0; a < 64; ++a) t[a] = e[a], e[a] = 0;
         sc(e, t)
      }

      function zs(e, t) {
         var a = H(),
            r = H(),
            n = H(),
            i = H(),
            s = H(),
            o = H(),
            u = H(),
            l = H(),
            c = H();
         la(a, e[1], e[0]), la(c, t[1], t[0]), de(a, a, c), ua(r, e[0], e[1]), ua(c, t[0], t[1]), de(r, r, c), de(n, e[3], t[3]), de(n, n, Op), de(i, e[2], t[2]), ua(i, i, i), la(s, r, a), la(o, i, n), ua(u, i, n), ua(l, r, a), de(e[0], s, o), de(e[1], l, u), de(e[2], u, o), de(e[3], s, l)
      }

      function ac(e, t, a) {
         for (var r = 0; r < 4; ++r) cc(e[r], t[r], a)
      }

      function Ws(e, t) {
         var a = H(),
            r = H(),
            n = H();
         Gp(n, t[2]), de(a, t[0], n), de(r, t[1], n), oi(e, r), e[31] ^= uc(a) << 7
      }

      function oi(e, t) {
         var a, r, n, i = H(),
            s = H();
         for (a = 0; a < 16; ++a) s[a] = t[a];
         for (Ks(s), Ks(s), Ks(s), r = 0; r < 2; ++r) {
            for (i[0] = s[0] - 65517, a = 1; a < 15; ++a) i[a] = s[a] - 65535 - (i[a - 1] >> 16 & 1), i[a - 1] &= 65535;
            i[15] = s[15] - 32767 - (i[14] >> 16 & 1), n = i[15] >> 16 & 1, i[14] &= 65535, cc(s, i, 1 - n)
         }
         for (a = 0; a < 16; a++) e[2 * a] = s[a] & 255, e[2 * a + 1] = s[a] >> 8
      }

      function Mp(e, t) {
         var a = H(),
            r = H(),
            n = H(),
            i = H(),
            s = H(),
            o = H(),
            u = H();
         return pr(e[2], si), Kp(e[1], t), _r(n, e[1]), de(i, n, kp), la(n, n, e[2]), ua(i, e[2], i), _r(s, i), _r(o, s), de(u, o, s), de(a, u, n), de(a, a, i), qp(a, a), de(a, a, n), de(a, a, i), de(a, a, i), de(e[0], a, i), _r(r, e[0]), de(r, r, i), nc(r, n) && de(e[0], e[0], Up), _r(r, e[0]), de(r, r, i), nc(r, n) ? -1 : (uc(e[0]) === t[31] >> 7 && la(e[0], Hs, e[0]), de(e[3], e[0], e[1]), 0)
      }

      function Kp(e, t) {
         var a;
         for (a = 0; a < 16; ++a) e[a] = t[2 * a] + (t[2 * a + 1] << 8);
         e[15] &= 32767
      }

      function qp(e, t) {
         var a = H(),
            r;
         for (r = 0; r < 16; ++r) a[r] = t[r];
         for (r = 250; r >= 0; --r) _r(a, a), r !== 1 && de(a, a, t);
         for (r = 0; r < 16; ++r) e[r] = a[r]
      }

      function nc(e, t) {
         var a = new ot(32),
            r = new ot(32);
         return oi(a, e), oi(r, t), oc(a, 0, r, 0)
      }

      function oc(e, t, a, r) {
         return Hp(e, t, a, r, 32)
      }

      function Hp(e, t, a, r, n) {
         var i, s = 0;
         for (i = 0; i < n; ++i) s |= e[t + i] ^ a[r + i];
         return (1 & s - 1 >>> 8) - 1
      }

      function uc(e) {
         var t = new ot(32);
         return oi(t, e), t[0] & 1
      }

      function lc(e, t, a) {
         var r, n;
         for (pr(e[0], Hs), pr(e[1], si), pr(e[2], si), pr(e[3], Hs), n = 255; n >= 0; --n) r = a[n / 8 | 0] >> (n & 7) & 1, ac(e, t, r), zs(t, e), zs(e, e), ac(e, t, r)
      }

      function Ys(e, t) {
         var a = [H(), H(), H(), H()];
         pr(a[0], tc), pr(a[1], rc), pr(a[2], si), de(a[3], tc, rc), lc(e, a, t)
      }

      function pr(e, t) {
         var a;
         for (a = 0; a < 16; a++) e[a] = t[a] | 0
      }

      function Gp(e, t) {
         var a = H(),
            r;
         for (r = 0; r < 16; ++r) a[r] = t[r];
         for (r = 253; r >= 0; --r) _r(a, a), r !== 2 && r !== 4 && de(a, a, t);
         for (r = 0; r < 16; ++r) e[r] = a[r]
      }

      function Ks(e) {
         var t, a, r = 1;
         for (t = 0; t < 16; ++t) a = e[t] + r + 65535, r = Math.floor(a / 65536), e[t] = a - r * 65536;
         e[0] += r - 1 + 37 * (r - 1)
      }

      function cc(e, t, a) {
         for (var r, n = ~(a - 1), i = 0; i < 16; ++i) r = n & (e[i] ^ t[i]), e[i] ^= r, t[i] ^= r
      }

      function H(e) {
         var t, a = new Float64Array(16);
         if (e)
            for (t = 0; t < e.length; ++t) a[t] = e[t];
         return a
      }

      function ua(e, t, a) {
         for (var r = 0; r < 16; ++r) e[r] = t[r] + a[r]
      }

      function la(e, t, a) {
         for (var r = 0; r < 16; ++r) e[r] = t[r] - a[r]
      }

      function _r(e, t) {
         de(e, t, t)
      }

      function de(e, t, a) {
         var r, n, i = 0,
            s = 0,
            o = 0,
            u = 0,
            l = 0,
            c = 0,
            f = 0,
            y = 0,
            g = 0,
            m = 0,
            x = 0,
            T = 0,
            I = 0,
            A = 0,
            B = 0,
            F = 0,
            R = 0,
            D = 0,
            G = 0,
            z = 0,
            oe = 0,
            ce = 0,
            pe = 0,
            ge = 0,
            et = 0,
            ht = 0,
            fe = 0,
            Ie = 0,
            M = 0,
            gr = 0,
            Ur = 0,
            be = a[0],
            Ae = a[1],
            we = a[2],
            Me = a[3],
            Ke = a[4],
            qe = a[5],
            He = a[6],
            Ge = a[7],
            ze = a[8],
            We = a[9],
            Ye = a[10],
            Ze = a[11],
            Qe = a[12],
            $e = a[13],
            je = a[14],
            Xe = a[15];
         r = t[0], i += r * be, s += r * Ae, o += r * we, u += r * Me, l += r * Ke, c += r * qe, f += r * He, y += r * Ge, g += r * ze, m += r * We, x += r * Ye, T += r * Ze, I += r * Qe, A += r * $e, B += r * je, F += r * Xe, r = t[1], s += r * be, o += r * Ae, u += r * we, l += r * Me, c += r * Ke, f += r * qe, y += r * He, g += r * Ge, m += r * ze, x += r * We, T += r * Ye, I += r * Ze, A += r * Qe, B += r * $e, F += r * je, R += r * Xe, r = t[2], o += r * be, u += r * Ae, l += r * we, c += r * Me, f += r * Ke, y += r * qe, g += r * He, m += r * Ge, x += r * ze, T += r * We, I += r * Ye, A += r * Ze, B += r * Qe, F += r * $e, R += r * je, D += r * Xe, r = t[3], u += r * be, l += r * Ae, c += r * we, f += r * Me, y += r * Ke, g += r * qe, m += r * He, x += r * Ge, T += r * ze, I += r * We, A += r * Ye, B += r * Ze, F += r * Qe, R += r * $e, D += r * je, G += r * Xe, r = t[4], l += r * be, c += r * Ae, f += r * we, y += r * Me, g += r * Ke, m += r * qe, x += r * He, T += r * Ge, I += r * ze, A += r * We, B += r * Ye, F += r * Ze, R += r * Qe, D += r * $e, G += r * je, z += r * Xe, r = t[5], c += r * be, f += r * Ae, y += r * we, g += r * Me, m += r * Ke, x += r * qe, T += r * He, I += r * Ge, A += r * ze, B += r * We, F += r * Ye, R += r * Ze, D += r * Qe, G += r * $e, z += r * je, oe += r * Xe, r = t[6], f += r * be, y += r * Ae, g += r * we, m += r * Me, x += r * Ke, T += r * qe, I += r * He, A += r * Ge, B += r * ze, F += r * We, R += r * Ye, D += r * Ze, G += r * Qe, z += r * $e, oe += r * je, ce += r * Xe, r = t[7], y += r * be, g += r * Ae, m += r * we, x += r * Me, T += r * Ke, I += r * qe, A += r * He, B += r * Ge, F += r * ze, R += r * We, D += r * Ye, G += r * Ze, z += r * Qe, oe += r * $e, ce += r * je, pe += r * Xe, r = t[8], g += r * be, m += r * Ae, x += r * we, T += r * Me, I += r * Ke, A += r * qe, B += r * He, F += r * Ge, R += r * ze, D += r * We, G += r * Ye, z += r * Ze, oe += r * Qe, ce += r * $e, pe += r * je, ge += r * Xe, r = t[9], m += r * be, x += r * Ae, T += r * we, I += r * Me, A += r * Ke, B += r * qe, F += r * He, R += r * Ge, D += r * ze, G += r * We, z += r * Ye, oe += r * Ze, ce += r * Qe, pe += r * $e, ge += r * je, et += r * Xe, r = t[10], x += r * be, T += r * Ae, I += r * we, A += r * Me, B += r * Ke, F += r * qe, R += r * He, D += r * Ge, G += r * ze, z += r * We, oe += r * Ye, ce += r * Ze, pe += r * Qe, ge += r * $e, et += r * je, ht += r * Xe, r = t[11], T += r * be, I += r * Ae, A += r * we, B += r * Me, F += r * Ke, R += r * qe, D += r * He, G += r * Ge, z += r * ze, oe += r * We, ce += r * Ye, pe += r * Ze, ge += r * Qe, et += r * $e, ht += r * je, fe += r * Xe, r = t[12], I += r * be, A += r * Ae, B += r * we, F += r * Me, R += r * Ke, D += r * qe, G += r * He, z += r * Ge, oe += r * ze, ce += r * We, pe += r * Ye, ge += r * Ze, et += r * Qe, ht += r * $e, fe += r * je, Ie += r * Xe, r = t[13], A += r * be, B += r * Ae, F += r * we, R += r * Me, D += r * Ke, G += r * qe, z += r * He, oe += r * Ge, ce += r * ze, pe += r * We, ge += r * Ye, et += r * Ze, ht += r * Qe, fe += r * $e, Ie += r * je, M += r * Xe, r = t[14], B += r * be, F += r * Ae, R += r * we, D += r * Me, G += r * Ke, z += r * qe, oe += r * He, ce += r * Ge, pe += r * ze, ge += r * We, et += r * Ye, ht += r * Ze, fe += r * Qe, Ie += r * $e, M += r * je, gr += r * Xe, r = t[15], F += r * be, R += r * Ae, D += r * we, G += r * Me, z += r * Ke, oe += r * qe, ce += r * He, pe += r * Ge, ge += r * ze, et += r * We, ht += r * Ye, fe += r * Ze, Ie += r * Qe, M += r * $e, gr += r * je, Ur += r * Xe, i += 38 * R, s += 38 * D, o += 38 * G, u += 38 * z, l += 38 * oe, c += 38 * ce, f += 38 * pe, y += 38 * ge, g += 38 * et, m += 38 * ht, x += 38 * fe, T += 38 * Ie, I += 38 * M, A += 38 * gr, B += 38 * Ur, n = 1, r = i + n + 65535, n = Math.floor(r / 65536), i = r - n * 65536, r = s + n + 65535, n = Math.floor(r / 65536), s = r - n * 65536, r = o + n + 65535, n = Math.floor(r / 65536), o = r - n * 65536, r = u + n + 65535, n = Math.floor(r / 65536), u = r - n * 65536, r = l + n + 65535, n = Math.floor(r / 65536), l = r - n * 65536, r = c + n + 65535, n = Math.floor(r / 65536), c = r - n * 65536, r = f + n + 65535, n = Math.floor(r / 65536), f = r - n * 65536, r = y + n + 65535, n = Math.floor(r / 65536), y = r - n * 65536, r = g + n + 65535, n = Math.floor(r / 65536), g = r - n * 65536, r = m + n + 65535, n = Math.floor(r / 65536), m = r - n * 65536, r = x + n + 65535, n = Math.floor(r / 65536), x = r - n * 65536, r = T + n + 65535, n = Math.floor(r / 65536), T = r - n * 65536, r = I + n + 65535, n = Math.floor(r / 65536), I = r - n * 65536, r = A + n + 65535, n = Math.floor(r / 65536), A = r - n * 65536, r = B + n + 65535, n = Math.floor(r / 65536), B = r - n * 65536, r = F + n + 65535, n = Math.floor(r / 65536), F = r - n * 65536, i += n - 1 + 37 * (n - 1), n = 1, r = i + n + 65535, n = Math.floor(r / 65536), i = r - n * 65536, r = s + n + 65535, n = Math.floor(r / 65536), s = r - n * 65536, r = o + n + 65535, n = Math.floor(r / 65536), o = r - n * 65536, r = u + n + 65535, n = Math.floor(r / 65536), u = r - n * 65536, r = l + n + 65535, n = Math.floor(r / 65536), l = r - n * 65536, r = c + n + 65535, n = Math.floor(r / 65536), c = r - n * 65536, r = f + n + 65535, n = Math.floor(r / 65536), f = r - n * 65536, r = y + n + 65535, n = Math.floor(r / 65536), y = r - n * 65536, r = g + n + 65535, n = Math.floor(r / 65536), g = r - n * 65536, r = m + n + 65535, n = Math.floor(r / 65536), m = r - n * 65536, r = x + n + 65535, n = Math.floor(r / 65536), x = r - n * 65536, r = T + n + 65535, n = Math.floor(r / 65536), T = r - n * 65536, r = I + n + 65535, n = Math.floor(r / 65536), I = r - n * 65536, r = A + n + 65535, n = Math.floor(r / 65536), A = r - n * 65536, r = B + n + 65535, n = Math.floor(r / 65536), B = r - n * 65536, r = F + n + 65535, n = Math.floor(r / 65536), F = r - n * 65536, i += n - 1 + 37 * (n - 1), e[0] = i, e[1] = s, e[2] = o, e[3] = u, e[4] = l, e[5] = c, e[6] = f, e[7] = y, e[8] = g, e[9] = m, e[10] = x, e[11] = T, e[12] = I, e[13] = A, e[14] = B, e[15] = F
      }
   });
   var mc = Y((Hg, yc) => {
      "use strict";
      var ct = $();
      ae();
      mt();
      tn();
      yc.exports = ct.kem = ct.kem || {};
      var dc = ct.jsbn.BigInteger;
      ct.kem.rsa = {};
      ct.kem.rsa.create = function(e, t) {
         t = t || {};
         var a = t.prng || ct.random,
            r = {};
         return r.encrypt = function(n, i) {
            var s = Math.ceil(n.n.bitLength() / 8),
               o;
            do o = new dc(ct.util.bytesToHex(a.getBytesSync(s)), 16).mod(n.n); while (o.compareTo(dc.ONE) <= 0);
            o = ct.util.hexToBytes(o.toString(16));
            var u = s - o.length;
            u > 0 && (o = ct.util.fillString(String.fromCharCode(0), u) + o);
            var l = n.encrypt(o, "NONE"),
               c = e.generate(o, i);
            return {
               encapsulation: l,
               key: c
            }
         }, r.decrypt = function(n, i, s) {
            var o = n.decrypt(i, "NONE");
            return e.generate(o, s)
         }, r
      };
      ct.kem.kdf1 = function(e, t) {
         pc(this, e, 0, t || e.digestLength)
      };
      ct.kem.kdf2 = function(e, t) {
         pc(this, e, 1, t || e.digestLength)
      };

      function pc(e, t, a, r) {
         e.generate = function(n, i) {
            for (var s = new ct.util.ByteBuffer, o = Math.ceil(i / r) + a, u = new ct.util.ByteBuffer, l = a; l < o; ++l) {
               u.putInt32(l), t.start(), t.update(n + u.getBytes());
               var c = t.digest();
               s.putBytes(c.getBytes(r))
            }
            return s.truncate(s.length() - i), s.getBytes()
         }
      }
   });
   var Cc = Y((Gg, Ec) => {
      "use strict";
      var ee = $();
      ae();
      Ec.exports = ee.log = ee.log || {};
      ee.log.levels = ["none", "error", "warning", "info", "debug", "verbose", "max"];
      var ui = {},
         $s = [],
         ln = null;
      ee.log.LEVEL_LOCKED = 2;
      ee.log.NO_LEVEL_CHECK = 4;
      ee.log.INTERPOLATE = 8;
      for (Mt = 0; Mt < ee.log.levels.length; ++Mt) Zs = ee.log.levels[Mt], ui[Zs] = {
         index: Mt,
         name: Zs.toUpperCase()
      };
      var Zs, Mt;
      ee.log.logMessage = function(e) {
         for (var t = ui[e.level].index, a = 0; a < $s.length; ++a) {
            var r = $s[a];
            if (r.flags & ee.log.NO_LEVEL_CHECK) r.f(e);
            else {
               var n = ui[r.level].index;
               t <= n && r.f(r, e)
            }
         }
      };
      ee.log.prepareStandard = function(e) {
         "standard" in e || (e.standard = ui[e.level].name + " [" + e.category + "] " + e.message)
      };
      ee.log.prepareFull = function(e) {
         if (!("full" in e)) {
            var t = [e.message];
            t = t.concat([]), e.full = ee.util.format.apply(this, t)
         }
      };
      ee.log.prepareStandardFull = function(e) {
         "standardFull" in e || (ee.log.prepareStandard(e), e.standardFull = e.standard)
      };
      for (Qs = ["error", "warning", "info", "debug", "verbose"], Mt = 0; Mt < Qs.length; ++Mt)(function(t) {
         ee.log[t] = function(a, r) {
            var n = Array.prototype.slice.call(arguments).slice(2),
               i = {
                  timestamp: new Date,
                  level: t,
                  category: a,
                  message: r,
                  arguments: n
               };
            ee.log.logMessage(i)
         }
      })(Qs[Mt]);
      var Qs, Mt;
      ee.log.makeLogger = function(e) {
         var t = {
            flags: 0,
            f: e
         };
         return ee.log.setLevel(t, "none"), t
      };
      ee.log.setLevel = function(e, t) {
         var a = !1;
         if (e && !(e.flags & ee.log.LEVEL_LOCKED))
            for (var r = 0; r < ee.log.levels.length; ++r) {
               var n = ee.log.levels[r];
               if (t == n) {
                  e.level = t, a = !0;
                  break
               }
            }
         return a
      };
      ee.log.lock = function(e, t) {
         typeof t > "u" || t ? e.flags |= ee.log.LEVEL_LOCKED : e.flags &= ~ee.log.LEVEL_LOCKED
      };
      ee.log.addLogger = function(e) {
         $s.push(e)
      };
      typeof console < "u" && "log" in console ? (console.error && console.warn && console.info && console.debug ? (gc = {
         error: console.error,
         warning: console.warn,
         info: console.info,
         debug: console.debug,
         verbose: console.debug
      }, cn = function(e, t) {
         ee.log.prepareStandard(t);
         var a = gc[t.level],
            r = [t.standard];
         r = r.concat(t.arguments.slice()), a.apply(console, r)
      }, ca = ee.log.makeLogger(cn)) : (cn = function(t, a) {
         ee.log.prepareStandardFull(a), console.log(a.standardFull)
      }, ca = ee.log.makeLogger(cn)), ee.log.setLevel(ca, "debug"), ee.log.addLogger(ca), ln = ca) : console = {
         log: function() {}
      };
      var ca, gc, cn;
      ln !== null && typeof window < "u" && window.location && (un = new URL(window.location.href).searchParams, un.has("console.level") && ee.log.setLevel(ln, un.get("console.level").slice(-1)[0]), un.has("console.lock") && (vc = un.get("console.lock").slice(-1)[0], vc == "true" && ee.log.lock(ln)));
      var un, vc;
      ee.log.consoleLogger = ln
   });
   var Tc = Y((zg, xc) => {
      "use strict";
      xc.exports = Rt();
      Kn();
      aa();
      ls();
      Ps()
   });
   var bc = Y((Wg, Ic) => {
      "use strict";
      var k = $();
      sr();
      wt();
      Ja();
      or();
      Sr();
      Ss();
      mt();
      ae();
      ti();
      var E = k.asn1,
         nt = Ic.exports = k.pkcs7 = k.pkcs7 || {};
      nt.messageFromPem = function(e) {
         var t = k.pem.decode(e)[0];
         if (t.type !== "PKCS7") {
            var a = new Error('Could not convert PKCS#7 message from PEM; PEM header type is not "PKCS#7".');
            throw a.headerType = t.type, a
         }
         if (t.procType && t.procType.type === "ENCRYPTED") throw new Error("Could not convert PKCS#7 message from PEM; PEM is encrypted.");
         var r = E.fromDer(t.body);
         return nt.messageFromAsn1(r)
      };
      nt.messageToPem = function(e, t) {
         var a = {
            type: "PKCS7",
            body: E.toDer(e.toAsn1()).getBytes()
         };
         return k.pem.encode(a, {
            maxline: t
         })
      };
      nt.messageFromAsn1 = function(e) {
         var t = {},
            a = [];
         if (!E.validate(e, nt.asn1.contentInfoValidator, t, a)) {
            var r = new Error("Cannot read PKCS#7 message. ASN.1 object is not an PKCS#7 ContentInfo.");
            throw r.errors = a, r
         }
         var n = E.derToOid(t.contentType),
            i;
         switch (n) {
            case k.pki.oids.envelopedData:
               i = nt.createEnvelopedData();
               break;
            case k.pki.oids.encryptedData:
               i = nt.createEncryptedData();
               break;
            case k.pki.oids.signedData:
               i = nt.createSignedData();
               break;
            default:
               throw new Error("Cannot read PKCS#7 message. ContentType with OID " + n + " is not (yet) supported.")
         }
         return i.fromAsn1(t.content.value[0]), i
      };
      nt.createSignedData = function() {
         var e = null;
         return e = {
            type: k.pki.oids.signedData,
            version: 1,
            certificates: [],
            crls: [],
            signers: [],
            digestAlgorithmIdentifiers: [],
            contentInfo: null,
            signerInfos: [],
            fromAsn1: function(r) {
               if (Xs(e, r, nt.asn1.signedDataValidator), e.certificates = [], e.crls = [], e.digestAlgorithmIdentifiers = [], e.contentInfo = null, e.signerInfos = [], e.rawCapture.certificates)
                  for (var n = e.rawCapture.certificates.value, i = 0; i < n.length; ++i) e.certificates.push(k.pki.certificateFromAsn1(n[i]))
            },
            toAsn1: function() {
               e.contentInfo || e.sign();
               for (var r = [], n = 0; n < e.certificates.length; ++n) r.push(k.pki.certificateToAsn1(e.certificates[n]));
               var i = [],
                  s = E.create(E.Class.CONTEXT_SPECIFIC, 0, !0, [E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.INTEGER, !1, E.integerToDer(e.version).getBytes()), E.create(E.Class.UNIVERSAL, E.Type.SET, !0, e.digestAlgorithmIdentifiers), e.contentInfo])]);
               return r.length > 0 && s.value[0].value.push(E.create(E.Class.CONTEXT_SPECIFIC, 0, !0, r)), i.length > 0 && s.value[0].value.push(E.create(E.Class.CONTEXT_SPECIFIC, 1, !0, i)), s.value[0].value.push(E.create(E.Class.UNIVERSAL, E.Type.SET, !0, e.signerInfos)), E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(e.type).getBytes()), s])
            },
            addSigner: function(r) {
               var n = r.issuer,
                  i = r.serialNumber;
               if (r.certificate) {
                  var s = r.certificate;
                  typeof s == "string" && (s = k.pki.certificateFromPem(s)), n = s.issuer.attributes, i = s.serialNumber
               }
               var o = r.key;
               if (!o) throw new Error("Could not add PKCS#7 signer; no private key specified.");
               typeof o == "string" && (o = k.pki.privateKeyFromPem(o));
               var u = r.digestAlgorithm || k.pki.oids.sha1;
               switch (u) {
                  case k.pki.oids.sha1:
                  case k.pki.oids.sha256:
                  case k.pki.oids.sha384:
                  case k.pki.oids.sha512:
                  case k.pki.oids.md5:
                     break;
                  default:
                     throw new Error("Could not add PKCS#7 signer; unknown message digest algorithm: " + u)
               }
               var l = r.authenticatedAttributes || [];
               if (l.length > 0) {
                  for (var c = !1, f = !1, y = 0; y < l.length; ++y) {
                     var g = l[y];
                     if (!c && g.type === k.pki.oids.contentType) {
                        if (c = !0, f) break;
                        continue
                     }
                     if (!f && g.type === k.pki.oids.messageDigest) {
                        if (f = !0, c) break;
                        continue
                     }
                  }
                  if (!c || !f) throw new Error("Invalid signer.authenticatedAttributes. If signer.authenticatedAttributes is specified, then it must contain at least two attributes, PKCS #9 content-type and PKCS #9 message-digest.")
               }
               e.signers.push({
                  key: o,
                  version: 1,
                  issuer: n,
                  serialNumber: i,
                  digestAlgorithm: u,
                  signatureAlgorithm: k.pki.oids.rsaEncryption,
                  signature: null,
                  authenticatedAttributes: l,
                  unauthenticatedAttributes: []
               })
            },
            sign: function(r) {
               if (r = r || {}, (typeof e.content != "object" || e.contentInfo === null) && (e.contentInfo = E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(k.pki.oids.data).getBytes())]), "content" in e)) {
                  var n;
                  e.content instanceof k.util.ByteBuffer ? n = e.content.bytes() : typeof e.content == "string" && (n = k.util.encodeUtf8(e.content)), r.detached ? e.detachedContent = E.create(E.Class.UNIVERSAL, E.Type.OCTETSTRING, !1, n) : e.contentInfo.value.push(E.create(E.Class.CONTEXT_SPECIFIC, 0, !0, [E.create(E.Class.UNIVERSAL, E.Type.OCTETSTRING, !1, n)]))
               }
               if (e.signers.length !== 0) {
                  var i = t();
                  a(i)
               }
            },
            verify: function() {
               throw new Error("PKCS#7 signature verification not yet implemented.")
            },
            addCertificate: function(r) {
               typeof r == "string" && (r = k.pki.certificateFromPem(r)), e.certificates.push(r)
            },
            addCertificateRevokationList: function(r) {
               throw new Error("PKCS#7 CRL support not yet implemented.")
            }
         }, e;

         function t() {
            for (var r = {}, n = 0; n < e.signers.length; ++n) {
               var i = e.signers[n],
                  s = i.digestAlgorithm;
               s in r || (r[s] = k.md[k.pki.oids[s]].create()), i.authenticatedAttributes.length === 0 ? i.md = r[s] : i.md = k.md[k.pki.oids[s]].create()
            }
            e.digestAlgorithmIdentifiers = [];
            for (var s in r) e.digestAlgorithmIdentifiers.push(E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(s).getBytes()), E.create(E.Class.UNIVERSAL, E.Type.NULL, !1, "")]));
            return r
         }

         function a(r) {
            var n;
            if (e.detachedContent ? n = e.detachedContent : (n = e.contentInfo.value[1], n = n.value[0]), !n) throw new Error("Could not sign PKCS#7 message; there is no content to sign.");
            var i = E.derToOid(e.contentInfo.value[0].value),
               s = E.toDer(n);
            s.getByte(), E.getBerValueLength(s), s = s.getBytes();
            for (var o in r) r[o].start().update(s);
            for (var u = new Date, l = 0; l < e.signers.length; ++l) {
               var c = e.signers[l];
               if (c.authenticatedAttributes.length === 0) {
                  if (i !== k.pki.oids.data) throw new Error("Invalid signer; authenticatedAttributes must be present when the ContentInfo content type is not PKCS#7 Data.")
               } else {
                  c.authenticatedAttributesAsn1 = E.create(E.Class.CONTEXT_SPECIFIC, 0, !0, []);
                  for (var f = E.create(E.Class.UNIVERSAL, E.Type.SET, !0, []), y = 0; y < c.authenticatedAttributes.length; ++y) {
                     var g = c.authenticatedAttributes[y];
                     g.type === k.pki.oids.messageDigest ? g.value = r[c.digestAlgorithm].digest() : g.type === k.pki.oids.signingTime && (g.value || (g.value = u)), f.value.push(js(g)), c.authenticatedAttributesAsn1.value.push(js(g))
                  }
                  s = E.toDer(f).getBytes(), c.md.start().update(s)
               }
               c.signature = c.key.sign(c.md, "RSASSA-PKCS1-V1_5")
            }
            e.signerInfos = $p(e.signers)
         }
      };
      nt.createEncryptedData = function() {
         var e = null;
         return e = {
            type: k.pki.oids.encryptedData,
            version: 0,
            encryptedContent: {
               algorithm: k.pki.oids["aes256-CBC"]
            },
            fromAsn1: function(t) {
               Xs(e, t, nt.asn1.encryptedDataValidator)
            },
            decrypt: function(t) {
               t !== void 0 && (e.encryptedContent.key = t), Sc(e)
            }
         }, e
      };
      nt.createEnvelopedData = function() {
         var e = null;
         return e = {
            type: k.pki.oids.envelopedData,
            version: 0,
            recipients: [],
            encryptedContent: {
               algorithm: k.pki.oids["aes256-CBC"]
            },
            fromAsn1: function(t) {
               var a = Xs(e, t, nt.asn1.envelopedDataValidator);
               e.recipients = Yp(a.recipientInfos.value)
            },
            toAsn1: function() {
               return E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(e.type).getBytes()), E.create(E.Class.CONTEXT_SPECIFIC, 0, !0, [E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.INTEGER, !1, E.integerToDer(e.version).getBytes()), E.create(E.Class.UNIVERSAL, E.Type.SET, !0, Zp(e.recipients)), E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, jp(e.encryptedContent))])])])
            },
            findRecipient: function(t) {
               for (var a = t.issuer.attributes, r = 0; r < e.recipients.length; ++r) {
                  var n = e.recipients[r],
                     i = n.issuer;
                  if (n.serialNumber === t.serialNumber && i.length === a.length) {
                     for (var s = !0, o = 0; o < a.length; ++o)
                        if (i[o].type !== a[o].type || i[o].value !== a[o].value) {
                           s = !1;
                           break
                        } if (s) return n
                  }
               }
               return null
            },
            decrypt: function(t, a) {
               if (e.encryptedContent.key === void 0 && t !== void 0 && a !== void 0) switch (t.encryptedContent.algorithm) {
                  case k.pki.oids.rsaEncryption:
                  case k.pki.oids.desCBC:
                     var r = a.decrypt(t.encryptedContent.content);
                     e.encryptedContent.key = k.util.createBuffer(r);
                     break;
                  default:
                     throw new Error("Unsupported asymmetric cipher, OID " + t.encryptedContent.algorithm)
               }
               Sc(e)
            },
            addRecipient: function(t) {
               e.recipients.push({
                  version: 0,
                  issuer: t.issuer.attributes,
                  serialNumber: t.serialNumber,
                  encryptedContent: {
                     algorithm: k.pki.oids.rsaEncryption,
                     key: t.publicKey
                  }
               })
            },
            encrypt: function(t, a) {
               if (e.encryptedContent.content === void 0) {
                  a = a || e.encryptedContent.algorithm, t = t || e.encryptedContent.key;
                  var r, n, i;
                  switch (a) {
                     case k.pki.oids["aes128-CBC"]:
                        r = 16, n = 16, i = k.aes.createEncryptionCipher;
                        break;
                     case k.pki.oids["aes192-CBC"]:
                        r = 24, n = 16, i = k.aes.createEncryptionCipher;
                        break;
                     case k.pki.oids["aes256-CBC"]:
                        r = 32, n = 16, i = k.aes.createEncryptionCipher;
                        break;
                     case k.pki.oids["des-EDE3-CBC"]:
                        r = 24, n = 8, i = k.des.createEncryptionCipher;
                        break;
                     default:
                        throw new Error("Unsupported symmetric cipher, OID " + a)
                  }
                  if (t === void 0) t = k.util.createBuffer(k.random.getBytes(r));
                  else if (t.length() != r) throw new Error("Symmetric key has wrong length; got " + t.length() + " bytes, expected " + r + ".");
                  e.encryptedContent.algorithm = a, e.encryptedContent.key = t, e.encryptedContent.parameter = k.util.createBuffer(k.random.getBytes(n));
                  var s = i(t);
                  if (s.start(e.encryptedContent.parameter.copy()), s.update(e.content), !s.finish()) throw new Error("Symmetric encryption failed.");
                  e.encryptedContent.content = s.output
               }
               for (var o = 0; o < e.recipients.length; ++o) {
                  var u = e.recipients[o];
                  if (u.encryptedContent.content === void 0) switch (u.encryptedContent.algorithm) {
                     case k.pki.oids.rsaEncryption:
                        u.encryptedContent.content = u.encryptedContent.key.encrypt(e.encryptedContent.key.data);
                        break;
                     default:
                        throw new Error("Unsupported asymmetric cipher, OID " + u.encryptedContent.algorithm)
                  }
               }
            }
         }, e
      };

      function zp(e) {
         var t = {},
            a = [];
         if (!E.validate(e, nt.asn1.recipientInfoValidator, t, a)) {
            var r = new Error("Cannot read PKCS#7 RecipientInfo. ASN.1 object is not an PKCS#7 RecipientInfo.");
            throw r.errors = a, r
         }
         return {
            version: t.version.charCodeAt(0),
            issuer: k.pki.RDNAttributesAsArray(t.issuer),
            serialNumber: k.util.createBuffer(t.serial).toHex(),
            encryptedContent: {
               algorithm: E.derToOid(t.encAlgorithm),
               parameter: t.encParameter ? t.encParameter.value : void 0,
               content: t.encKey
            }
         }
      }

      function Wp(e) {
         return E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.INTEGER, !1, E.integerToDer(e.version).getBytes()), E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [k.pki.distinguishedNameToAsn1({
            attributes: e.issuer
         }), E.create(E.Class.UNIVERSAL, E.Type.INTEGER, !1, k.util.hexToBytes(e.serialNumber))]), E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(e.encryptedContent.algorithm).getBytes()), E.create(E.Class.UNIVERSAL, E.Type.NULL, !1, "")]), E.create(E.Class.UNIVERSAL, E.Type.OCTETSTRING, !1, e.encryptedContent.content)])
      }

      function Yp(e) {
         for (var t = [], a = 0; a < e.length; ++a) t.push(zp(e[a]));
         return t
      }

      function Zp(e) {
         for (var t = [], a = 0; a < e.length; ++a) t.push(Wp(e[a]));
         return t
      }

      function Qp(e) {
         var t = E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.INTEGER, !1, E.integerToDer(e.version).getBytes()), E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [k.pki.distinguishedNameToAsn1({
            attributes: e.issuer
         }), E.create(E.Class.UNIVERSAL, E.Type.INTEGER, !1, k.util.hexToBytes(e.serialNumber))]), E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(e.digestAlgorithm).getBytes()), E.create(E.Class.UNIVERSAL, E.Type.NULL, !1, "")])]);
         if (e.authenticatedAttributesAsn1 && t.value.push(e.authenticatedAttributesAsn1), t.value.push(E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(e.signatureAlgorithm).getBytes()), E.create(E.Class.UNIVERSAL, E.Type.NULL, !1, "")])), t.value.push(E.create(E.Class.UNIVERSAL, E.Type.OCTETSTRING, !1, e.signature)), e.unauthenticatedAttributes.length > 0) {
            for (var a = E.create(E.Class.CONTEXT_SPECIFIC, 1, !0, []), r = 0; r < e.unauthenticatedAttributes.length; ++r) {
               var n = e.unauthenticatedAttributes[r];
               a.values.push(js(n))
            }
            t.value.push(a)
         }
         return t
      }

      function $p(e) {
         for (var t = [], a = 0; a < e.length; ++a) t.push(Qp(e[a]));
         return t
      }

      function js(e) {
         var t;
         if (e.type === k.pki.oids.contentType) t = E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(e.value).getBytes());
         else if (e.type === k.pki.oids.messageDigest) t = E.create(E.Class.UNIVERSAL, E.Type.OCTETSTRING, !1, e.value.bytes());
         else if (e.type === k.pki.oids.signingTime) {
            var a = new Date("1950-01-01T00:00:00Z"),
               r = new Date("2050-01-01T00:00:00Z"),
               n = e.value;
            if (typeof n == "string") {
               var i = Date.parse(n);
               isNaN(i) ? n.length === 13 ? n = E.utcTimeToDate(n) : n = E.generalizedTimeToDate(n) : n = new Date(i)
            }
            n >= a && n < r ? t = E.create(E.Class.UNIVERSAL, E.Type.UTCTIME, !1, E.dateToUtcTime(n)) : t = E.create(E.Class.UNIVERSAL, E.Type.GENERALIZEDTIME, !1, E.dateToGeneralizedTime(n))
         }
         return E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(e.type).getBytes()), E.create(E.Class.UNIVERSAL, E.Type.SET, !0, [t])])
      }

      function jp(e) {
         return [E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(k.pki.oids.data).getBytes()), E.create(E.Class.UNIVERSAL, E.Type.SEQUENCE, !0, [E.create(E.Class.UNIVERSAL, E.Type.OID, !1, E.oidToDer(e.algorithm).getBytes()), e.parameter ? E.create(E.Class.UNIVERSAL, E.Type.OCTETSTRING, !1, e.parameter.getBytes()) : void 0]), E.create(E.Class.CONTEXT_SPECIFIC, 0, !0, [E.create(E.Class.UNIVERSAL, E.Type.OCTETSTRING, !1, e.content.getBytes())])]
      }

      function Xs(e, t, a) {
         var r = {},
            n = [];
         if (!E.validate(t, a, r, n)) {
            var i = new Error("Cannot read PKCS#7 message. ASN.1 object is not a supported PKCS#7 message.");
            throw i.errors = i, i
         }
         var s = E.derToOid(r.contentType);
         if (s !== k.pki.oids.data) throw new Error("Unsupported PKCS#7 message. Only wrapped ContentType Data supported.");
         if (r.encryptedContent) {
            var o = "";
            if (k.util.isArray(r.encryptedContent))
               for (var u = 0; u < r.encryptedContent.length; ++u) {
                  if (r.encryptedContent[u].type !== E.Type.OCTETSTRING) throw new Error("Malformed PKCS#7 message, expecting encrypted content constructed of only OCTET STRING objects.");
                  o += r.encryptedContent[u].value
               } else o = r.encryptedContent;
            e.encryptedContent = {
               algorithm: E.derToOid(r.encAlgorithm),
               parameter: k.util.createBuffer(r.encParameter.value),
               content: k.util.createBuffer(o)
            }
         }
         if (r.content) {
            var o = "";
            if (k.util.isArray(r.content))
               for (var u = 0; u < r.content.length; ++u) {
                  if (r.content[u].type !== E.Type.OCTETSTRING) throw new Error("Malformed PKCS#7 message, expecting content constructed of only OCTET STRING objects.");
                  o += r.content[u].value
               } else o = r.content;
            e.content = k.util.createBuffer(o)
         }
         return e.version = r.version.charCodeAt(0), e.rawCapture = r, r
      }

      function Sc(e) {
         if (e.encryptedContent.key === void 0) throw new Error("Symmetric key not available.");
         if (e.content === void 0) {
            var t;
            switch (e.encryptedContent.algorithm) {
               case k.pki.oids["aes128-CBC"]:
               case k.pki.oids["aes192-CBC"]:
               case k.pki.oids["aes256-CBC"]:
                  t = k.aes.createDecryptionCipher(e.encryptedContent.key);
                  break;
               case k.pki.oids.desCBC:
               case k.pki.oids["des-EDE3-CBC"]:
                  t = k.des.createDecryptionCipher(e.encryptedContent.key);
                  break;
               default:
                  throw new Error("Unsupported symmetric cipher, OID " + e.encryptedContent.algorithm)
            }
            if (t.start(e.encryptedContent.parameter), t.update(e.encryptedContent.content), !t.finish()) throw new Error("Symmetric decryption failed.");
            e.content = t.output
         }
      }
   });
   var Bc = Y((Yg, Ac) => {
      "use strict";
      var Be = $();
      sr();
      Jr();
      Kn();
      aa();
      ae();
      var ci = Ac.exports = Be.ssh = Be.ssh || {};
      ci.privateKeyToPutty = function(e, t, a) {
         a = a || "", t = t || "";
         var r = "ssh-rsa",
            n = t === "" ? "none" : "aes256-cbc",
            i = "PuTTY-User-Key-File-2: " + r + `\r
`;
         i += "Encryption: " + n + `\r
`, i += "Comment: " + a + `\r
`;
         var s = Be.util.createBuffer();
         fa(s, r), Kt(s, e.e), Kt(s, e.n);
         var o = Be.util.encode64(s.bytes(), 64),
            u = Math.floor(o.length / 66) + 1;
         i += "Public-Lines: " + u + `\r
`, i += o;
         var l = Be.util.createBuffer();
         Kt(l, e.d), Kt(l, e.p), Kt(l, e.q), Kt(l, e.qInv);
         var c;
         if (!t) c = Be.util.encode64(l.bytes(), 64);
         else {
            var f = l.length() + 16 - 1;
            f -= f % 16;
            var y = li(l.bytes());
            y.truncate(y.length() - f + l.length()), l.putBuffer(y);
            var g = Be.util.createBuffer();
            g.putBuffer(li("\0\0\0\0", t)), g.putBuffer(li("\0\0\0", t));
            var m = Be.aes.createEncryptionCipher(g.truncate(8), "CBC");
            m.start(Be.util.createBuffer().fillWithByte(0, 16)), m.update(l.copy()), m.finish();
            var x = m.output;
            x.truncate(16), c = Be.util.encode64(x.bytes(), 64)
         }
         u = Math.floor(c.length / 66) + 1, i += `\r
Private-Lines: ` + u + `\r
`, i += c;
         var T = li("putty-private-key-file-mac-key", t),
            I = Be.util.createBuffer();
         fa(I, r), fa(I, n), fa(I, a), I.putInt32(s.length()), I.putBuffer(s), I.putInt32(l.length()), I.putBuffer(l);
         var A = Be.hmac.create();
         return A.start("sha1", T), A.update(I.bytes()), i += `\r
Private-MAC: ` + A.digest().toHex() + `\r
`, i
      };
      ci.publicKeyToOpenSSH = function(e, t) {
         var a = "ssh-rsa";
         t = t || "";
         var r = Be.util.createBuffer();
         return fa(r, a), Kt(r, e.e), Kt(r, e.n), a + " " + Be.util.encode64(r.bytes()) + " " + t
      };
      ci.privateKeyToOpenSSH = function(e, t) {
         return t ? Be.pki.encryptRsaPrivateKey(e, t, {
            legacy: !0,
            algorithm: "aes128"
         }) : Be.pki.privateKeyToPem(e)
      };
      ci.getPublicKeyFingerprint = function(e, t) {
         t = t || {};
         var a = t.md || Be.md.md5.create(),
            r = "ssh-rsa",
            n = Be.util.createBuffer();
         fa(n, r), Kt(n, e.e), Kt(n, e.n), a.start(), a.update(n.getBytes());
         var i = a.digest();
         if (t.encoding === "hex") {
            var s = i.toHex();
            return t.delimiter ? s.match(/.{2}/g).join(t.delimiter) : s
         } else {
            if (t.encoding === "binary") return i.getBytes();
            if (t.encoding) throw new Error('Unknown encoding "' + t.encoding + '".')
         }
         return i
      };

      function Kt(e, t) {
         var a = t.toString(16);
         a[0] >= "8" && (a = "00" + a);
         var r = Be.util.hexToBytes(a);
         e.putInt32(r.length), e.putBytes(r)
      }

      function fa(e, t) {
         e.putInt32(t.length), e.putString(t)
      }

      function li() {
         for (var e = Be.md.sha1.create(), t = arguments.length, a = 0; a < t; ++a) e.update(arguments[a]);
         return e.digest()
      }
   });
   var ha = Y((Zg, wc) => {
      "use strict";
      wc.exports = $();
      sr();
      Zl();
      wt();
      kn();
      Ja();
      hc();
      Jr();
      mc();
      Cc();
      Tc();
      Is();
      zn();
      Sr();
      vs();
      Bs();
      bc();
      Ns();
      Cs();
      cs();
      Xn();
      mt();
      ds();
      Bc();
      Os();
      ae()
   });
   var oy = {};
   Hc(oy, {
      Certificate: () => ma,
      Credential: () => yn,
      DataArrayTrait: () => Dr,
      KeyTrait: () => Lr,
      KeyType: () => ya,
      KeyTypeEnum: () => dn,
      LocalFileOpenTrait: () => ft,
      PemExtractor: () => Rr,
      PfxExporter: () => no,
      PfxReader: () => io,
      PrivateKey: () => ga,
      PublicKey: () => kr,
      Rfc4514: () => hn,
      SatType: () => di,
      SatTypeEnum: () => pa,
      SerialNumber: () => Or,
      isNumber: () => to,
      isScalar: () => hi
   });
   var qt = class extends Error {},
      vn = class extends qt {
         constructor(t) {
            super(`Invalid DateTime: ${t.toMessage()}`)
         }
      },
      En = class extends qt {
         constructor(t) {
            super(`Invalid Interval: ${t.toMessage()}`)
         }
      },
      Cn = class extends qt {
         constructor(t) {
            super(`Invalid Duration: ${t.toMessage()}`)
         }
      },
      Ht = class extends qt {},
      Fr = class extends qt {
         constructor(t) {
            super(`Invalid unit ${t}`)
         }
      },
      Ne = class extends qt {},
      St = class extends qt {
         constructor() {
            super("Zone is an abstract class")
         }
      };
   var O = "numeric",
      It = "short",
      ut = "long",
      Xt = {
         year: O,
         month: O,
         day: O
      },
      Ca = {
         year: O,
         month: It,
         day: O
      },
      pi = {
         year: O,
         month: It,
         day: O,
         weekday: It
      },
      xa = {
         year: O,
         month: ut,
         day: O
      },
      Ta = {
         year: O,
         month: ut,
         day: O,
         weekday: ut
      },
      Sa = {
         hour: O,
         minute: O
      },
      Ia = {
         hour: O,
         minute: O,
         second: O
      },
      ba = {
         hour: O,
         minute: O,
         second: O,
         timeZoneName: It
      },
      Aa = {
         hour: O,
         minute: O,
         second: O,
         timeZoneName: ut
      },
      Ba = {
         hour: O,
         minute: O,
         hourCycle: "h23"
      },
      wa = {
         hour: O,
         minute: O,
         second: O,
         hourCycle: "h23"
      },
      Na = {
         hour: O,
         minute: O,
         second: O,
         hourCycle: "h23",
         timeZoneName: It
      },
      _a = {
         hour: O,
         minute: O,
         second: O,
         hourCycle: "h23",
         timeZoneName: ut
      },
      Da = {
         year: O,
         month: O,
         day: O,
         hour: O,
         minute: O
      },
      Ra = {
         year: O,
         month: O,
         day: O,
         hour: O,
         minute: O,
         second: O
      },
      La = {
         year: O,
         month: It,
         day: O,
         hour: O,
         minute: O
      },
      ka = {
         year: O,
         month: It,
         day: O,
         hour: O,
         minute: O,
         second: O
      },
      yi = {
         year: O,
         month: It,
         day: O,
         weekday: It,
         hour: O,
         minute: O
      },
      Oa = {
         year: O,
         month: ut,
         day: O,
         hour: O,
         minute: O,
         timeZoneName: It
      },
      Ua = {
         year: O,
         month: ut,
         day: O,
         hour: O,
         minute: O,
         second: O,
         timeZoneName: It
      },
      Fa = {
         year: O,
         month: ut,
         day: O,
         weekday: ut,
         hour: O,
         minute: O,
         timeZoneName: ut
      },
      Pa = {
         year: O,
         month: ut,
         day: O,
         weekday: ut,
         hour: O,
         minute: O,
         second: O,
         timeZoneName: ut
      };
   var it = class {
      get type() {
         throw new St
      }
      get name() {
         throw new St
      }
      get ianaName() {
         return this.name
      }
      get isUniversal() {
         throw new St
      }
      offsetName(t, a) {
         throw new St
      }
      formatOffset(t, a) {
         throw new St
      }
      offset(t) {
         throw new St
      }
      equals(t) {
         throw new St
      }
      get isValid() {
         throw new St
      }
   };
   var mi = null,
      Jt = class e extends it {
         static get instance() {
            return mi === null && (mi = new e), mi
         }
         get type() {
            return "system"
         }
         get name() {
            return new Intl.DateTimeFormat().resolvedOptions().timeZone
         }
         get isUniversal() {
            return !1
         }
         offsetName(t, {
            format: a,
            locale: r
         }) {
            return Tn(t, a, r)
         }
         formatOffset(t, a) {
            return er(this.offset(t), a)
         }
         offset(t) {
            return -new Date(t).getTimezoneOffset()
         }
         equals(t) {
            return t.type === "system"
         }
         get isValid() {
            return !0
         }
      };
   var In = {};

   function zc(e) {
      return In[e] || (In[e] = new Intl.DateTimeFormat("en-US", {
         hour12: !1,
         timeZone: e,
         year: "numeric",
         month: "2-digit",
         day: "2-digit",
         hour: "2-digit",
         minute: "2-digit",
         second: "2-digit",
         era: "short"
      })), In[e]
   }
   var Wc = {
      year: 0,
      month: 1,
      day: 2,
      era: 3,
      hour: 4,
      minute: 5,
      second: 6
   };

   function Yc(e, t) {
      let a = e.format(t).replace(/\u200E/g, ""),
         r = /(\d+)\/(\d+)\/(\d+) (AD|BC),? (\d+):(\d+):(\d+)/.exec(a),
         [, n, i, s, o, u, l, c] = r;
      return [s, n, i, o, u, l, c]
   }

   function Zc(e, t) {
      let a = e.formatToParts(t),
         r = [];
      for (let n = 0; n < a.length; n++) {
         let {
            type: i,
            value: s
         } = a[n], o = Wc[i];
         i === "era" ? r[o] = s : Q(o) || (r[o] = parseInt(s, 10))
      }
      return r
   }
   var Sn = {},
      Je = class e extends it {
         static create(t) {
            return Sn[t] || (Sn[t] = new e(t)), Sn[t]
         }
         static resetCache() {
            Sn = {}, In = {}
         }
         static isValidSpecifier(t) {
            return this.isValidZone(t)
         }
         static isValidZone(t) {
            if (!t) return !1;
            try {
               return new Intl.DateTimeFormat("en-US", {
                  timeZone: t
               }).format(), !0
            } catch {
               return !1
            }
         }
         constructor(t) {
            super(), this.zoneName = t, this.valid = e.isValidZone(t)
         }
         get type() {
            return "iana"
         }
         get name() {
            return this.zoneName
         }
         get isUniversal() {
            return !1
         }
         offsetName(t, {
            format: a,
            locale: r
         }) {
            return Tn(t, a, r, this.name)
         }
         formatOffset(t, a) {
            return er(this.offset(t), a)
         }
         offset(t) {
            let a = new Date(t);
            if (isNaN(a)) return NaN;
            let r = zc(this.name),
               [n, i, s, o, u, l, c] = r.formatToParts ? Zc(r, a) : Yc(r, a);
            o === "BC" && (n = -Math.abs(n) + 1);
            let y = Va({
                  year: n,
                  month: i,
                  day: s,
                  hour: u === 24 ? 0 : u,
                  minute: l,
                  second: c,
                  millisecond: 0
               }),
               g = +a,
               m = g % 1e3;
            return g -= m >= 0 ? m : 1e3 + m, (y - g) / (60 * 1e3)
         }
         equals(t) {
            return t.type === "iana" && t.name === this.name
         }
         get isValid() {
            return this.valid
         }
      };
   var oo = {};

   function Qc(e, t = {}) {
      let a = JSON.stringify([e, t]),
         r = oo[a];
      return r || (r = new Intl.ListFormat(e, t), oo[a] = r), r
   }
   var gi = {};

   function vi(e, t = {}) {
      let a = JSON.stringify([e, t]),
         r = gi[a];
      return r || (r = new Intl.DateTimeFormat(e, t), gi[a] = r), r
   }
   var Ei = {};

   function $c(e, t = {}) {
      let a = JSON.stringify([e, t]),
         r = Ei[a];
      return r || (r = new Intl.NumberFormat(e, t), Ei[a] = r), r
   }
   var Ci = {};

   function jc(e, t = {}) {
      let {
         base: a,
         ...r
      } = t, n = JSON.stringify([e, r]), i = Ci[n];
      return i || (i = new Intl.RelativeTimeFormat(e, t), Ci[n] = i), i
   }
   var Ma = null;

   function Xc() {
      return Ma || (Ma = new Intl.DateTimeFormat().resolvedOptions().locale, Ma)
   }

   function Jc(e) {
      let t = e.indexOf("-x-");
      t !== -1 && (e = e.substring(0, t));
      let a = e.indexOf("-u-");
      if (a === -1) return [e];
      {
         let r, n;
         try {
            r = vi(e).resolvedOptions(), n = e
         } catch {
            let u = e.substring(0, a);
            r = vi(u).resolvedOptions(), n = u
         }
         let {
            numberingSystem: i,
            calendar: s
         } = r;
         return [n, i, s]
      }
   }

   function ef(e, t, a) {
      return (a || t) && (e.includes("-u-") || (e += "-u"), a && (e += `-ca-${a}`), t && (e += `-nu-${t}`)), e
   }

   function tf(e) {
      let t = [];
      for (let a = 1; a <= 12; a++) {
         let r = ie.utc(2016, a, 1);
         t.push(e(r))
      }
      return t
   }

   function rf(e) {
      let t = [];
      for (let a = 1; a <= 7; a++) {
         let r = ie.utc(2016, 11, 13 + a);
         t.push(e(r))
      }
      return t
   }

   function bn(e, t, a, r, n) {
      let i = e.listingMode(a);
      return i === "error" ? null : i === "en" ? r(t) : n(t)
   }

   function af(e) {
      return e.numberingSystem && e.numberingSystem !== "latn" ? !1 : e.numberingSystem === "latn" || !e.locale || e.locale.startsWith("en") || new Intl.DateTimeFormat(e.intl).resolvedOptions().numberingSystem === "latn"
   }
   var xi = class {
         constructor(t, a, r) {
            this.padTo = r.padTo || 0, this.floor = r.floor || !1;
            let {
               padTo: n,
               floor: i,
               ...s
            } = r;
            if (!a || Object.keys(s).length > 0) {
               let o = {
                  useGrouping: !1,
                  ...r
               };
               r.padTo > 0 && (o.minimumIntegerDigits = r.padTo), this.inf = $c(t, o)
            }
         }
         format(t) {
            if (this.inf) {
               let a = this.floor ? Math.floor(t) : t;
               return this.inf.format(a)
            } else {
               let a = this.floor ? Math.floor(t) : Pr(t, 3);
               return xe(a, this.padTo)
            }
         }
      },
      Ti = class {
         constructor(t, a, r) {
            this.opts = r, this.originalZone = void 0;
            let n;
            if (this.opts.timeZone) this.dt = t;
            else if (t.zone.type === "fixed") {
               let s = -1 * (t.offset / 60),
                  o = s >= 0 ? `Etc/GMT+${s}` : `Etc/GMT${s}`;
               t.offset !== 0 && Je.create(o).valid ? (n = o, this.dt = t) : (n = "UTC", this.dt = t.offset === 0 ? t : t.setZone("UTC").plus({
                  minutes: t.offset
               }), this.originalZone = t.zone)
            } else t.zone.type === "system" ? this.dt = t : t.zone.type === "iana" ? (this.dt = t, n = t.zone.name) : (n = "UTC", this.dt = t.setZone("UTC").plus({
               minutes: t.offset
            }), this.originalZone = t.zone);
            let i = {
               ...this.opts
            };
            i.timeZone = i.timeZone || n, this.dtf = vi(a, i)
         }
         format() {
            return this.originalZone ? this.formatToParts().map(({
               value: t
            }) => t).join("") : this.dtf.format(this.dt.toJSDate())
         }
         formatToParts() {
            let t = this.dtf.formatToParts(this.dt.toJSDate());
            return this.originalZone ? t.map(a => {
               if (a.type === "timeZoneName") {
                  let r = this.originalZone.offsetName(this.dt.ts, {
                     locale: this.dt.locale,
                     format: this.opts.timeZoneName
                  });
                  return {
                     ...a,
                     value: r
                  }
               } else return a
            }) : t
         }
         resolvedOptions() {
            return this.dtf.resolvedOptions()
         }
      },
      Si = class {
         constructor(t, a, r) {
            this.opts = {
               style: "long",
               ...r
            }, !a && An() && (this.rtf = jc(t, r))
         }
         format(t, a) {
            return this.rtf ? this.rtf.format(t, a) : uo(a, t, this.opts.numeric, this.opts.style !== "long")
         }
         formatToParts(t, a) {
            return this.rtf ? this.rtf.formatToParts(t, a) : []
         }
      },
      he = class e {
         static fromOpts(t) {
            return e.create(t.locale, t.numberingSystem, t.outputCalendar, t.defaultToEN)
         }
         static create(t, a, r, n = !1) {
            let i = t || ue.defaultLocale,
               s = i || (n ? "en-US" : Xc()),
               o = a || ue.defaultNumberingSystem,
               u = r || ue.defaultOutputCalendar;
            return new e(s, o, u, i)
         }
         static resetCache() {
            Ma = null, gi = {}, Ei = {}, Ci = {}
         }
         static fromObject({
            locale: t,
            numberingSystem: a,
            outputCalendar: r
         } = {}) {
            return e.create(t, a, r)
         }
         constructor(t, a, r, n) {
            let [i, s, o] = Jc(t);
            this.locale = i, this.numberingSystem = a || s || null, this.outputCalendar = r || o || null, this.intl = ef(this.locale, this.numberingSystem, this.outputCalendar), this.weekdaysCache = {
               format: {},
               standalone: {}
            }, this.monthsCache = {
               format: {},
               standalone: {}
            }, this.meridiemCache = null, this.eraCache = {}, this.specifiedLocale = n, this.fastNumbersCached = null
         }
         get fastNumbers() {
            return this.fastNumbersCached == null && (this.fastNumbersCached = af(this)), this.fastNumbersCached
         }
         listingMode() {
            let t = this.isEnglish(),
               a = (this.numberingSystem === null || this.numberingSystem === "latn") && (this.outputCalendar === null || this.outputCalendar === "gregory");
            return t && a ? "en" : "intl"
         }
         clone(t) {
            return !t || Object.getOwnPropertyNames(t).length === 0 ? this : e.create(t.locale || this.specifiedLocale, t.numberingSystem || this.numberingSystem, t.outputCalendar || this.outputCalendar, t.defaultToEN || !1)
         }
         redefaultToEN(t = {}) {
            return this.clone({
               ...t,
               defaultToEN: !0
            })
         }
         redefaultToSystem(t = {}) {
            return this.clone({
               ...t,
               defaultToEN: !1
            })
         }
         months(t, a = !1, r = !0) {
            return bn(this, t, r, Ii, () => {
               let n = a ? {
                     month: t,
                     day: "numeric"
                  } : {
                     month: t
                  },
                  i = a ? "format" : "standalone";
               return this.monthsCache[i][t] || (this.monthsCache[i][t] = tf(s => this.extract(s, n, "month"))), this.monthsCache[i][t]
            })
         }
         weekdays(t, a = !1, r = !0) {
            return bn(this, t, r, bi, () => {
               let n = a ? {
                     weekday: t,
                     year: "numeric",
                     month: "long",
                     day: "numeric"
                  } : {
                     weekday: t
                  },
                  i = a ? "format" : "standalone";
               return this.weekdaysCache[i][t] || (this.weekdaysCache[i][t] = rf(s => this.extract(s, n, "weekday"))), this.weekdaysCache[i][t]
            })
         }
         meridiems(t = !0) {
            return bn(this, void 0, t, () => Ai, () => {
               if (!this.meridiemCache) {
                  let a = {
                     hour: "numeric",
                     hourCycle: "h12"
                  };
                  this.meridiemCache = [ie.utc(2016, 11, 13, 9), ie.utc(2016, 11, 13, 19)].map(r => this.extract(r, a, "dayperiod"))
               }
               return this.meridiemCache
            })
         }
         eras(t, a = !0) {
            return bn(this, t, a, Bi, () => {
               let r = {
                  era: t
               };
               return this.eraCache[t] || (this.eraCache[t] = [ie.utc(-40, 1, 1), ie.utc(2017, 1, 1)].map(n => this.extract(n, r, "era"))), this.eraCache[t]
            })
         }
         extract(t, a, r) {
            let n = this.dtFormatter(t, a),
               i = n.formatToParts(),
               s = i.find(o => o.type.toLowerCase() === r);
            return s ? s.value : null
         }
         numberFormatter(t = {}) {
            return new xi(this.intl, t.forceSimple || this.fastNumbers, t)
         }
         dtFormatter(t, a = {}) {
            return new Ti(t, this.intl, a)
         }
         relFormatter(t = {}) {
            return new Si(this.intl, this.isEnglish(), t)
         }
         listFormatter(t = {}) {
            return Qc(this.intl, t)
         }
         isEnglish() {
            return this.locale === "en" || this.locale.toLowerCase() === "en-us" || new Intl.DateTimeFormat(this.intl).resolvedOptions().locale.startsWith("en-us")
         }
         equals(t) {
            return this.locale === t.locale && this.numberingSystem === t.numberingSystem && this.outputCalendar === t.outputCalendar
         }
      };
   var Ni = null,
      _e = class e extends it {
         static get utcInstance() {
            return Ni === null && (Ni = new e(0)), Ni
         }
         static instance(t) {
            return t === 0 ? e.utcInstance : new e(t)
         }
         static parseSpecifier(t) {
            if (t) {
               let a = t.match(/^utc(?:([+-]\d{1,2})(?::(\d{2}))?)?$/i);
               if (a) return new e(vr(a[1], a[2]))
            }
            return null
         }
         constructor(t) {
            super(), this.fixed = t
         }
         get type() {
            return "fixed"
         }
         get name() {
            return this.fixed === 0 ? "UTC" : `UTC${er(this.fixed,"narrow")}`
         }
         get ianaName() {
            return this.fixed === 0 ? "Etc/UTC" : `Etc/GMT${er(-this.fixed,"narrow")}`
         }
         offsetName() {
            return this.name
         }
         formatOffset(t, a) {
            return er(this.fixed, a)
         }
         get isUniversal() {
            return !0
         }
         offset() {
            return this.fixed
         }
         equals(t) {
            return t.type === "fixed" && t.fixed === this.fixed
         }
         get isValid() {
            return !0
         }
      };
   var Vr = class extends it {
      constructor(t) {
         super(), this.zoneName = t
      }
      get type() {
         return "invalid"
      }
      get name() {
         return this.zoneName
      }
      get isUniversal() {
         return !1
      }
      offsetName() {
         return null
      }
      formatOffset() {
         return ""
      }
      offset() {
         return NaN
      }
      equals() {
         return !1
      }
      get isValid() {
         return !1
      }
   };

   function bt(e, t) {
      let a;
      if (Q(e) || e === null) return t;
      if (e instanceof it) return e;
      if (lo(e)) {
         let r = e.toLowerCase();
         return r === "default" ? t : r === "local" || r === "system" ? Jt.instance : r === "utc" || r === "gmt" ? _e.utcInstance : _e.parseSpecifier(r) || Je.create(e)
      } else return _t(e) ? _e.instance(e) : typeof e == "object" && e.offset && typeof e.offset == "number" ? e : new Vr(e)
   }
   var co = () => Date.now(),
      fo = "system",
      ho = null,
      po = null,
      yo = null,
      mo = 60,
      go, ue = class {
         static get now() {
            return co
         }
         static set now(t) {
            co = t
         }
         static set defaultZone(t) {
            fo = t
         }
         static get defaultZone() {
            return bt(fo, Jt.instance)
         }
         static get defaultLocale() {
            return ho
         }
         static set defaultLocale(t) {
            ho = t
         }
         static get defaultNumberingSystem() {
            return po
         }
         static set defaultNumberingSystem(t) {
            po = t
         }
         static get defaultOutputCalendar() {
            return yo
         }
         static set defaultOutputCalendar(t) {
            yo = t
         }
         static get twoDigitCutoffYear() {
            return mo
         }
         static set twoDigitCutoffYear(t) {
            mo = t % 100
         }
         static get throwOnInvalid() {
            return go
         }
         static set throwOnInvalid(t) {
            go = t
         }
         static resetCaches() {
            he.resetCache(), Je.resetCache()
         }
      };

   function Q(e) {
      return typeof e > "u"
   }

   function _t(e) {
      return typeof e == "number"
   }

   function Ka(e) {
      return typeof e == "number" && e % 1 === 0
   }

   function lo(e) {
      return typeof e == "string"
   }

   function vo(e) {
      return Object.prototype.toString.call(e) === "[object Date]"
   }

   function An() {
      try {
         return typeof Intl < "u" && !!Intl.RelativeTimeFormat
      } catch {
         return !1
      }
   }

   function Eo(e) {
      return Array.isArray(e) ? e : [e]
   }

   function _i(e, t, a) {
      if (e.length !== 0) return e.reduce((r, n) => {
         let i = [t(n), n];
         return r && a(r[0], i[0]) === r[0] ? r : i
      }, null)[1]
   }

   function Co(e, t) {
      return t.reduce((a, r) => (a[r] = e[r], a), {})
   }

   function tr(e, t) {
      return Object.prototype.hasOwnProperty.call(e, t)
   }

   function Dt(e, t, a) {
      return Ka(e) && e >= t && e <= a
   }

   function nf(e, t) {
      return e - t * Math.floor(e / t)
   }

   function xe(e, t = 2) {
      let a = e < 0,
         r;
      return a ? r = "-" + ("" + -e).padStart(t, "0") : r = ("" + e).padStart(t, "0"), r
   }

   function Gt(e) {
      if (!(Q(e) || e === null || e === "")) return parseInt(e, 10)
   }

   function rr(e) {
      if (!(Q(e) || e === null || e === "")) return parseFloat(e)
   }

   function qa(e) {
      if (!(Q(e) || e === null || e === "")) {
         let t = parseFloat("0." + e) * 1e3;
         return Math.floor(t)
      }
   }

   function Pr(e, t, a = !1) {
      let r = 10 ** t;
      return (a ? Math.trunc : Math.round)(e * r) / r
   }

   function Er(e) {
      return e % 4 === 0 && (e % 100 !== 0 || e % 400 === 0)
   }

   function Cr(e) {
      return Er(e) ? 366 : 365
   }

   function Mr(e, t) {
      let a = nf(t - 1, 12) + 1,
         r = e + (t - a) / 12;
      return a === 2 ? Er(r) ? 29 : 28 : [31, null, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][a - 1]
   }

   function Va(e) {
      let t = Date.UTC(e.year, e.month - 1, e.day, e.hour, e.minute, e.second, e.millisecond);
      return e.year < 100 && e.year >= 0 && (t = new Date(t), t.setUTCFullYear(e.year, e.month - 1, e.day)), +t
   }

   function Kr(e) {
      let t = (e + Math.floor(e / 4) - Math.floor(e / 100) + Math.floor(e / 400)) % 7,
         a = e - 1,
         r = (a + Math.floor(a / 4) - Math.floor(a / 100) + Math.floor(a / 400)) % 7;
      return t === 4 || r === 3 ? 53 : 52
   }

   function Ha(e) {
      return e > 99 ? e : e > ue.twoDigitCutoffYear ? 1900 + e : 2e3 + e
   }

   function Tn(e, t, a, r = null) {
      let n = new Date(e),
         i = {
            hourCycle: "h23",
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit"
         };
      r && (i.timeZone = r);
      let s = {
            timeZoneName: t,
            ...i
         },
         o = new Intl.DateTimeFormat(a, s).formatToParts(n).find(u => u.type.toLowerCase() === "timezonename");
      return o ? o.value : null
   }

   function vr(e, t) {
      let a = parseInt(e, 10);
      Number.isNaN(a) && (a = 0);
      let r = parseInt(t, 10) || 0,
         n = a < 0 || Object.is(a, -0) ? -r : r;
      return a * 60 + n
   }

   function Di(e) {
      let t = Number(e);
      if (typeof e == "boolean" || e === "" || Number.isNaN(t)) throw new Ne(`Invalid unit value ${e}`);
      return t
   }

   function qr(e, t) {
      let a = {};
      for (let r in e)
         if (tr(e, r)) {
            let n = e[r];
            if (n == null) continue;
            a[t(r)] = Di(n)
         } return a
   }

   function er(e, t) {
      let a = Math.trunc(Math.abs(e / 60)),
         r = Math.trunc(Math.abs(e % 60)),
         n = e >= 0 ? "+" : "-";
      switch (t) {
         case "short":
            return `${n}${xe(a,2)}:${xe(r,2)}`;
         case "narrow":
            return `${n}${a}${r>0?`:${r}`:""}`;
         case "techie":
            return `${n}${xe(a,2)}${xe(r,2)}`;
         default:
            throw new RangeError(`Value format ${t} is out of range for property format`)
      }
   }

   function Ga(e) {
      return Co(e, ["hour", "minute", "second", "millisecond"])
   }
   var sf = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"],
      Ri = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
      of = ["J", "F", "M", "A", "M", "J", "J", "A", "S", "O", "N", "D"];

   function Ii(e) {
      switch (e) {
         case "narrow":
            return [...of];
         case "short":
            return [...Ri];
         case "long":
            return [...sf];
         case "numeric":
            return ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"];
         case "2-digit":
            return ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"];
         default:
            return null
      }
   }
   var Li = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
      ki = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
      uf = ["M", "T", "W", "T", "F", "S", "S"];

   function bi(e) {
      switch (e) {
         case "narrow":
            return [...uf];
         case "short":
            return [...ki];
         case "long":
            return [...Li];
         case "numeric":
            return ["1", "2", "3", "4", "5", "6", "7"];
         default:
            return null
      }
   }
   var Ai = ["AM", "PM"],
      lf = ["Before Christ", "Anno Domini"],
      cf = ["BC", "AD"],
      ff = ["B", "A"];

   function Bi(e) {
      switch (e) {
         case "narrow":
            return [...ff];
         case "short":
            return [...cf];
         case "long":
            return [...lf];
         default:
            return null
      }
   }

   function xo(e) {
      return Ai[e.hour < 12 ? 0 : 1]
   }

   function To(e, t) {
      return bi(t)[e.weekday - 1]
   }

   function So(e, t) {
      return Ii(t)[e.month - 1]
   }

   function Io(e, t) {
      return Bi(t)[e.year < 0 ? 0 : 1]
   }

   function uo(e, t, a = "always", r = !1) {
      let n = {
            years: ["year", "yr."],
            quarters: ["quarter", "qtr."],
            months: ["month", "mo."],
            weeks: ["week", "wk."],
            days: ["day", "day", "days"],
            hours: ["hour", "hr."],
            minutes: ["minute", "min."],
            seconds: ["second", "sec."]
         },
         i = ["hours", "minutes", "seconds"].indexOf(e) === -1;
      if (a === "auto" && i) {
         let f = e === "days";
         switch (t) {
            case 1:
               return f ? "tomorrow" : `next ${n[e][0]}`;
            case -1:
               return f ? "yesterday" : `last ${n[e][0]}`;
            case 0:
               return f ? "today" : `this ${n[e][0]}`;
            default:
         }
      }
      let s = Object.is(t, -0) || t < 0,
         o = Math.abs(t),
         u = o === 1,
         l = n[e],
         c = r ? u ? l[1] : l[2] || l[1] : u ? n[e][0] : e;
      return s ? `${o} ${c} ago` : `in ${o} ${c}`
   }

   function bo(e, t) {
      let a = "";
      for (let r of e) r.literal ? a += r.val : a += t(r.val);
      return a
   }
   var hf = {
         D: Xt,
         DD: Ca,
         DDD: xa,
         DDDD: Ta,
         t: Sa,
         tt: Ia,
         ttt: ba,
         tttt: Aa,
         T: Ba,
         TT: wa,
         TTT: Na,
         TTTT: _a,
         f: Da,
         ff: La,
         fff: Oa,
         ffff: Fa,
         F: Ra,
         FF: ka,
         FFF: Ua,
         FFFF: Pa
      },
      De = class e {
         static create(t, a = {}) {
            return new e(t, a)
         }
         static parseFormat(t) {
            let a = null,
               r = "",
               n = !1,
               i = [];
            for (let s = 0; s < t.length; s++) {
               let o = t.charAt(s);
               o === "'" ? (r.length > 0 && i.push({
                  literal: n || /^\s+$/.test(r),
                  val: r
               }), a = null, r = "", n = !n) : n || o === a ? r += o : (r.length > 0 && i.push({
                  literal: /^\s+$/.test(r),
                  val: r
               }), r = o, a = o)
            }
            return r.length > 0 && i.push({
               literal: n || /^\s+$/.test(r),
               val: r
            }), i
         }
         static macroTokenToFormatOpts(t) {
            return hf[t]
         }
         constructor(t, a) {
            this.opts = a, this.loc = t, this.systemLoc = null
         }
         formatWithSystemDefault(t, a) {
            return this.systemLoc === null && (this.systemLoc = this.loc.redefaultToSystem()), this.systemLoc.dtFormatter(t, {
               ...this.opts,
               ...a
            }).format()
         }
         formatDateTime(t, a = {}) {
            return this.loc.dtFormatter(t, {
               ...this.opts,
               ...a
            }).format()
         }
         formatDateTimeParts(t, a = {}) {
            return this.loc.dtFormatter(t, {
               ...this.opts,
               ...a
            }).formatToParts()
         }
         formatInterval(t, a = {}) {
            return this.loc.dtFormatter(t.start, {
               ...this.opts,
               ...a
            }).dtf.formatRange(t.start.toJSDate(), t.end.toJSDate())
         }
         resolvedOptions(t, a = {}) {
            return this.loc.dtFormatter(t, {
               ...this.opts,
               ...a
            }).resolvedOptions()
         }
         num(t, a = 0) {
            if (this.opts.forceSimple) return xe(t, a);
            let r = {
               ...this.opts
            };
            return a > 0 && (r.padTo = a), this.loc.numberFormatter(r).format(t)
         }
         formatDateTimeFromString(t, a) {
            let r = this.loc.listingMode() === "en",
               n = this.loc.outputCalendar && this.loc.outputCalendar !== "gregory",
               i = (g, m) => this.loc.extract(t, g, m),
               s = g => t.isOffsetFixed && t.offset === 0 && g.allowZ ? "Z" : t.isValid ? t.zone.formatOffset(t.ts, g.format) : "",
               o = () => r ? xo(t) : i({
                  hour: "numeric",
                  hourCycle: "h12"
               }, "dayperiod"),
               u = (g, m) => r ? So(t, g) : i(m ? {
                  month: g
               } : {
                  month: g,
                  day: "numeric"
               }, "month"),
               l = (g, m) => r ? To(t, g) : i(m ? {
                  weekday: g
               } : {
                  weekday: g,
                  month: "long",
                  day: "numeric"
               }, "weekday"),
               c = g => {
                  let m = e.macroTokenToFormatOpts(g);
                  return m ? this.formatWithSystemDefault(t, m) : g
               },
               f = g => r ? Io(t, g) : i({
                  era: g
               }, "era"),
               y = g => {
                  switch (g) {
                     case "S":
                        return this.num(t.millisecond);
                     case "u":
                     case "SSS":
                        return this.num(t.millisecond, 3);
                     case "s":
                        return this.num(t.second);
                     case "ss":
                        return this.num(t.second, 2);
                     case "uu":
                        return this.num(Math.floor(t.millisecond / 10), 2);
                     case "uuu":
                        return this.num(Math.floor(t.millisecond / 100));
                     case "m":
                        return this.num(t.minute);
                     case "mm":
                        return this.num(t.minute, 2);
                     case "h":
                        return this.num(t.hour % 12 === 0 ? 12 : t.hour % 12);
                     case "hh":
                        return this.num(t.hour % 12 === 0 ? 12 : t.hour % 12, 2);
                     case "H":
                        return this.num(t.hour);
                     case "HH":
                        return this.num(t.hour, 2);
                     case "Z":
                        return s({
                           format: "narrow",
                           allowZ: this.opts.allowZ
                        });
                     case "ZZ":
                        return s({
                           format: "short",
                           allowZ: this.opts.allowZ
                        });
                     case "ZZZ":
                        return s({
                           format: "techie",
                           allowZ: this.opts.allowZ
                        });
                     case "ZZZZ":
                        return t.zone.offsetName(t.ts, {
                           format: "short",
                           locale: this.loc.locale
                        });
                     case "ZZZZZ":
                        return t.zone.offsetName(t.ts, {
                           format: "long",
                           locale: this.loc.locale
                        });
                     case "z":
                        return t.zoneName;
                     case "a":
                        return o();
                     case "d":
                        return n ? i({
                           day: "numeric"
                        }, "day") : this.num(t.day);
                     case "dd":
                        return n ? i({
                           day: "2-digit"
                        }, "day") : this.num(t.day, 2);
                     case "c":
                        return this.num(t.weekday);
                     case "ccc":
                        return l("short", !0);
                     case "cccc":
                        return l("long", !0);
                     case "ccccc":
                        return l("narrow", !0);
                     case "E":
                        return this.num(t.weekday);
                     case "EEE":
                        return l("short", !1);
                     case "EEEE":
                        return l("long", !1);
                     case "EEEEE":
                        return l("narrow", !1);
                     case "L":
                        return n ? i({
                           month: "numeric",
                           day: "numeric"
                        }, "month") : this.num(t.month);
                     case "LL":
                        return n ? i({
                           month: "2-digit",
                           day: "numeric"
                        }, "month") : this.num(t.month, 2);
                     case "LLL":
                        return u("short", !0);
                     case "LLLL":
                        return u("long", !0);
                     case "LLLLL":
                        return u("narrow", !0);
                     case "M":
                        return n ? i({
                           month: "numeric"
                        }, "month") : this.num(t.month);
                     case "MM":
                        return n ? i({
                           month: "2-digit"
                        }, "month") : this.num(t.month, 2);
                     case "MMM":
                        return u("short", !1);
                     case "MMMM":
                        return u("long", !1);
                     case "MMMMM":
                        return u("narrow", !1);
                     case "y":
                        return n ? i({
                           year: "numeric"
                        }, "year") : this.num(t.year);
                     case "yy":
                        return n ? i({
                           year: "2-digit"
                        }, "year") : this.num(t.year.toString().slice(-2), 2);
                     case "yyyy":
                        return n ? i({
                           year: "numeric"
                        }, "year") : this.num(t.year, 4);
                     case "yyyyyy":
                        return n ? i({
                           year: "numeric"
                        }, "year") : this.num(t.year, 6);
                     case "G":
                        return f("short");
                     case "GG":
                        return f("long");
                     case "GGGGG":
                        return f("narrow");
                     case "kk":
                        return this.num(t.weekYear.toString().slice(-2), 2);
                     case "kkkk":
                        return this.num(t.weekYear, 4);
                     case "W":
                        return this.num(t.weekNumber);
                     case "WW":
                        return this.num(t.weekNumber, 2);
                     case "o":
                        return this.num(t.ordinal);
                     case "ooo":
                        return this.num(t.ordinal, 3);
                     case "q":
                        return this.num(t.quarter);
                     case "qq":
                        return this.num(t.quarter, 2);
                     case "X":
                        return this.num(Math.floor(t.ts / 1e3));
                     case "x":
                        return this.num(t.ts);
                     default:
                        return c(g)
                  }
               };
            return bo(e.parseFormat(a), y)
         }
         formatDurationFromString(t, a) {
            let r = u => {
                  switch (u[0]) {
                     case "S":
                        return "millisecond";
                     case "s":
                        return "second";
                     case "m":
                        return "minute";
                     case "h":
                        return "hour";
                     case "d":
                        return "day";
                     case "w":
                        return "week";
                     case "M":
                        return "month";
                     case "y":
                        return "year";
                     default:
                        return null
                  }
               },
               n = u => l => {
                  let c = r(l);
                  return c ? this.num(u.get(c), l.length) : l
               },
               i = e.parseFormat(a),
               s = i.reduce((u, {
                  literal: l,
                  val: c
               }) => l ? u : u.concat(c), []),
               o = t.shiftTo(...s.map(r).filter(u => u));
            return bo(i, n(o))
         }
      };
   var Re = class {
      constructor(t, a) {
         this.reason = t, this.explanation = a
      }
      toMessage() {
         return this.explanation ? `${this.reason}: ${this.explanation}` : this.reason
      }
   };
   var Bo = /[A-Za-z_+-]{1,256}(?::?\/[A-Za-z0-9_+-]{1,256}(?:\/[A-Za-z0-9_+-]{1,256})?)?/;

   function Gr(...e) {
      let t = e.reduce((a, r) => a + r.source, "");
      return RegExp(`^${t}$`)
   }

   function zr(...e) {
      return t => e.reduce(([a, r, n], i) => {
         let [s, o, u] = i(t, n);
         return [{
            ...a,
            ...s
         }, o || r, u]
      }, [{}, null, 1]).slice(0, 2)
   }

   function Wr(e, ...t) {
      if (e == null) return [null, null];
      for (let [a, r] of t) {
         let n = a.exec(e);
         if (n) return r(n)
      }
      return [null, null]
   }

   function wo(...e) {
      return (t, a) => {
         let r = {},
            n;
         for (n = 0; n < e.length; n++) r[e[n]] = Gt(t[a + n]);
         return [r, null, a + n]
      }
   }
   var No = /(?:(Z)|([+-]\d\d)(?::?(\d\d))?)/,
      df = `(?:${No.source}?(?:\\[(${Bo.source})\\])?)?`,
      Oi = /(\d\d)(?::?(\d\d)(?::?(\d\d)(?:[.,](\d{1,30}))?)?)?/,
      _o = RegExp(`${Oi.source}${df}`),
      Ui = RegExp(`(?:T${_o.source})?`),
      pf = /([+-]\d{6}|\d{4})(?:-?(\d\d)(?:-?(\d\d))?)?/,
      yf = /(\d{4})-?W(\d\d)(?:-?(\d))?/,
      mf = /(\d{4})-?(\d{3})/,
      gf = wo("weekYear", "weekNumber", "weekDay"),
      vf = wo("year", "ordinal"),
      Ef = /(\d{4})-(\d\d)-(\d\d)/,
      Do = RegExp(`${Oi.source} ?(?:${No.source}|(${Bo.source}))?`),
      Cf = RegExp(`(?: ${Do.source})?`);

   function Hr(e, t, a) {
      let r = e[t];
      return Q(r) ? a : Gt(r)
   }

   function xf(e, t) {
      return [{
         year: Hr(e, t),
         month: Hr(e, t + 1, 1),
         day: Hr(e, t + 2, 1)
      }, null, t + 3]
   }

   function Yr(e, t) {
      return [{
         hours: Hr(e, t, 0),
         minutes: Hr(e, t + 1, 0),
         seconds: Hr(e, t + 2, 0),
         milliseconds: qa(e[t + 3])
      }, null, t + 4]
   }

   function za(e, t) {
      let a = !e[t] && !e[t + 1],
         r = vr(e[t + 1], e[t + 2]),
         n = a ? null : _e.instance(r);
      return [{}, n, t + 3]
   }

   function Wa(e, t) {
      let a = e[t] ? Je.create(e[t]) : null;
      return [{}, a, t + 1]
   }
   var Tf = RegExp(`^T?${Oi.source}$`),
      Sf = /^-?P(?:(?:(-?\d{1,20}(?:\.\d{1,20})?)Y)?(?:(-?\d{1,20}(?:\.\d{1,20})?)M)?(?:(-?\d{1,20}(?:\.\d{1,20})?)W)?(?:(-?\d{1,20}(?:\.\d{1,20})?)D)?(?:T(?:(-?\d{1,20}(?:\.\d{1,20})?)H)?(?:(-?\d{1,20}(?:\.\d{1,20})?)M)?(?:(-?\d{1,20})(?:[.,](-?\d{1,20}))?S)?)?)$/;

   function If(e) {
      let [t, a, r, n, i, s, o, u, l] = e, c = t[0] === "-", f = u && u[0] === "-", y = (g, m = !1) => g !== void 0 && (m || g && c) ? -g : g;
      return [{
         years: y(rr(a)),
         months: y(rr(r)),
         weeks: y(rr(n)),
         days: y(rr(i)),
         hours: y(rr(s)),
         minutes: y(rr(o)),
         seconds: y(rr(u), u === "-0"),
         milliseconds: y(qa(l), f)
      }]
   }
   var bf = {
      GMT: 0,
      EDT: -4 * 60,
      EST: -5 * 60,
      CDT: -5 * 60,
      CST: -6 * 60,
      MDT: -6 * 60,
      MST: -7 * 60,
      PDT: -7 * 60,
      PST: -8 * 60
   };

   function Fi(e, t, a, r, n, i, s) {
      let o = {
         year: t.length === 2 ? Ha(Gt(t)) : Gt(t),
         month: Ri.indexOf(a) + 1,
         day: Gt(r),
         hour: Gt(n),
         minute: Gt(i)
      };
      return s && (o.second = Gt(s)), e && (o.weekday = e.length > 3 ? Li.indexOf(e) + 1 : ki.indexOf(e) + 1), o
   }
   var Af = /^(?:(Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s)?(\d{1,2})\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s(\d{2,4})\s(\d\d):(\d\d)(?::(\d\d))?\s(?:(UT|GMT|[ECMP][SD]T)|([Zz])|(?:([+-]\d\d)(\d\d)))$/;

   function Bf(e) {
      let [, t, a, r, n, i, s, o, u, l, c, f] = e, y = Fi(t, n, r, a, i, s, o), g;
      return u ? g = bf[u] : l ? g = 0 : g = vr(c, f), [y, new _e(g)]
   }

   function wf(e) {
      return e.replace(/\([^()]*\)|[\n\t]/g, " ").replace(/(\s\s+)/g, " ").trim()
   }
   var Nf = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d\d) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d\d):(\d\d):(\d\d) GMT$/,
      _f = /^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d\d)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d\d) (\d\d):(\d\d):(\d\d) GMT$/,
      Df = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( \d|\d\d) (\d\d):(\d\d):(\d\d) (\d{4})$/;

   function Ao(e) {
      let [, t, a, r, n, i, s, o] = e;
      return [Fi(t, n, r, a, i, s, o), _e.utcInstance]
   }

   function Rf(e) {
      let [, t, a, r, n, i, s, o] = e;
      return [Fi(t, o, a, r, n, i, s), _e.utcInstance]
   }
   var Lf = Gr(pf, Ui),
      kf = Gr(yf, Ui),
      Of = Gr(mf, Ui),
      Uf = Gr(_o),
      Ro = zr(xf, Yr, za, Wa),
      Ff = zr(gf, Yr, za, Wa),
      Pf = zr(vf, Yr, za, Wa),
      Vf = zr(Yr, za, Wa);

   function Lo(e) {
      return Wr(e, [Lf, Ro], [kf, Ff], [Of, Pf], [Uf, Vf])
   }

   function ko(e) {
      return Wr(wf(e), [Af, Bf])
   }

   function Oo(e) {
      return Wr(e, [Nf, Ao], [_f, Ao], [Df, Rf])
   }

   function Uo(e) {
      return Wr(e, [Sf, If])
   }
   var Mf = zr(Yr);

   function Fo(e) {
      return Wr(e, [Tf, Mf])
   }
   var Kf = Gr(Ef, Cf),
      qf = Gr(Do),
      Hf = zr(Yr, za, Wa);

   function Po(e) {
      return Wr(e, [Kf, Ro], [qf, Hf])
   }
   var Gf = "Invalid Duration",
      Vo = {
         weeks: {
            days: 7,
            hours: 7 * 24,
            minutes: 7 * 24 * 60,
            seconds: 7 * 24 * 60 * 60,
            milliseconds: 7 * 24 * 60 * 60 * 1e3
         },
         days: {
            hours: 24,
            minutes: 24 * 60,
            seconds: 24 * 60 * 60,
            milliseconds: 24 * 60 * 60 * 1e3
         },
         hours: {
            minutes: 60,
            seconds: 60 * 60,
            milliseconds: 60 * 60 * 1e3
         },
         minutes: {
            seconds: 60,
            milliseconds: 60 * 1e3
         },
         seconds: {
            milliseconds: 1e3
         }
      },
      zf = {
         years: {
            quarters: 4,
            months: 12,
            weeks: 52,
            days: 365,
            hours: 365 * 24,
            minutes: 365 * 24 * 60,
            seconds: 365 * 24 * 60 * 60,
            milliseconds: 365 * 24 * 60 * 60 * 1e3
         },
         quarters: {
            months: 3,
            weeks: 13,
            days: 91,
            hours: 91 * 24,
            minutes: 91 * 24 * 60,
            seconds: 91 * 24 * 60 * 60,
            milliseconds: 91 * 24 * 60 * 60 * 1e3
         },
         months: {
            weeks: 4,
            days: 30,
            hours: 30 * 24,
            minutes: 30 * 24 * 60,
            seconds: 30 * 24 * 60 * 60,
            milliseconds: 30 * 24 * 60 * 60 * 1e3
         },
         ...Vo
      },
      dt = 146097 / 400,
      Zr = 146097 / 4800,
      Wf = {
         years: {
            quarters: 4,
            months: 12,
            weeks: dt / 7,
            days: dt,
            hours: dt * 24,
            minutes: dt * 24 * 60,
            seconds: dt * 24 * 60 * 60,
            milliseconds: dt * 24 * 60 * 60 * 1e3
         },
         quarters: {
            months: 3,
            weeks: dt / 28,
            days: dt / 4,
            hours: dt * 24 / 4,
            minutes: dt * 24 * 60 / 4,
            seconds: dt * 24 * 60 * 60 / 4,
            milliseconds: dt * 24 * 60 * 60 * 1e3 / 4
         },
         months: {
            weeks: Zr / 7,
            days: Zr,
            hours: Zr * 24,
            minutes: Zr * 24 * 60,
            seconds: Zr * 24 * 60 * 60,
            milliseconds: Zr * 24 * 60 * 60 * 1e3
         },
         ...Vo
      },
      xr = ["years", "quarters", "months", "weeks", "days", "hours", "minutes", "seconds", "milliseconds"],
      Yf = xr.slice(0).reverse();

   function ar(e, t, a = !1) {
      let r = {
         values: a ? t.values : {
            ...e.values,
            ...t.values || {}
         },
         loc: e.loc.clone(t.loc),
         conversionAccuracy: t.conversionAccuracy || e.conversionAccuracy,
         matrix: t.matrix || e.matrix
      };
      return new Te(r)
   }

   function Zf(e) {
      return e < 0 ? Math.floor(e) : Math.ceil(e)
   }

   function Mo(e, t, a, r, n) {
      let i = e[n][a],
         s = t[a] / i,
         o = Math.sign(s) === Math.sign(r[n]),
         u = !o && r[n] !== 0 && Math.abs(s) <= 1 ? Zf(s) : Math.trunc(s);
      r[n] += u, t[a] -= u * i
   }

   function Qf(e, t) {
      Yf.reduce((a, r) => Q(t[r]) ? a : (a && Mo(e, t, a, t, r), r), null)
   }

   function $f(e) {
      let t = {};
      for (let [a, r] of Object.entries(e)) r !== 0 && (t[a] = r);
      return t
   }
   var Te = class e {
      constructor(t) {
         let a = t.conversionAccuracy === "longterm" || !1,
            r = a ? Wf : zf;
         t.matrix && (r = t.matrix), this.values = t.values, this.loc = t.loc || he.create(), this.conversionAccuracy = a ? "longterm" : "casual", this.invalid = t.invalid || null, this.matrix = r, this.isLuxonDuration = !0
      }
      static fromMillis(t, a) {
         return e.fromObject({
            milliseconds: t
         }, a)
      }
      static fromObject(t, a = {}) {
         if (t == null || typeof t != "object") throw new Ne(`Duration.fromObject: argument expected to be an object, got ${t===null?"null":typeof t}`);
         return new e({
            values: qr(t, e.normalizeUnit),
            loc: he.fromObject(a),
            conversionAccuracy: a.conversionAccuracy,
            matrix: a.matrix
         })
      }
      static fromDurationLike(t) {
         if (_t(t)) return e.fromMillis(t);
         if (e.isDuration(t)) return t;
         if (typeof t == "object") return e.fromObject(t);
         throw new Ne(`Unknown duration argument ${t} of type ${typeof t}`)
      }
      static fromISO(t, a) {
         let [r] = Uo(t);
         return r ? e.fromObject(r, a) : e.invalid("unparsable", `the input "${t}" can't be parsed as ISO 8601`)
      }
      static fromISOTime(t, a) {
         let [r] = Fo(t);
         return r ? e.fromObject(r, a) : e.invalid("unparsable", `the input "${t}" can't be parsed as ISO 8601`)
      }
      static invalid(t, a = null) {
         if (!t) throw new Ne("need to specify a reason the Duration is invalid");
         let r = t instanceof Re ? t : new Re(t, a);
         if (ue.throwOnInvalid) throw new Cn(r);
         return new e({
            invalid: r
         })
      }
      static normalizeUnit(t) {
         let a = {
            year: "years",
            years: "years",
            quarter: "quarters",
            quarters: "quarters",
            month: "months",
            months: "months",
            week: "weeks",
            weeks: "weeks",
            day: "days",
            days: "days",
            hour: "hours",
            hours: "hours",
            minute: "minutes",
            minutes: "minutes",
            second: "seconds",
            seconds: "seconds",
            millisecond: "milliseconds",
            milliseconds: "milliseconds"
         } [t && t.toLowerCase()];
         if (!a) throw new Fr(t);
         return a
      }
      static isDuration(t) {
         return t && t.isLuxonDuration || !1
      }
      get locale() {
         return this.isValid ? this.loc.locale : null
      }
      get numberingSystem() {
         return this.isValid ? this.loc.numberingSystem : null
      }
      toFormat(t, a = {}) {
         let r = {
            ...a,
            floor: a.round !== !1 && a.floor !== !1
         };
         return this.isValid ? De.create(this.loc, r).formatDurationFromString(this, t) : Gf
      }
      toHuman(t = {}) {
         let a = xr.map(r => {
            let n = this.values[r];
            return Q(n) ? null : this.loc.numberFormatter({
               style: "unit",
               unitDisplay: "long",
               ...t,
               unit: r.slice(0, -1)
            }).format(n)
         }).filter(r => r);
         return this.loc.listFormatter({
            type: "conjunction",
            style: t.listStyle || "narrow",
            ...t
         }).format(a)
      }
      toObject() {
         return this.isValid ? {
            ...this.values
         } : {}
      }
      toISO() {
         if (!this.isValid) return null;
         let t = "P";
         return this.years !== 0 && (t += this.years + "Y"), (this.months !== 0 || this.quarters !== 0) && (t += this.months + this.quarters * 3 + "M"), this.weeks !== 0 && (t += this.weeks + "W"), this.days !== 0 && (t += this.days + "D"), (this.hours !== 0 || this.minutes !== 0 || this.seconds !== 0 || this.milliseconds !== 0) && (t += "T"), this.hours !== 0 && (t += this.hours + "H"), this.minutes !== 0 && (t += this.minutes + "M"), (this.seconds !== 0 || this.milliseconds !== 0) && (t += Pr(this.seconds + this.milliseconds / 1e3, 3) + "S"), t === "P" && (t += "T0S"), t
      }
      toISOTime(t = {}) {
         if (!this.isValid) return null;
         let a = this.toMillis();
         if (a < 0 || a >= 864e5) return null;
         t = {
            suppressMilliseconds: !1,
            suppressSeconds: !1,
            includePrefix: !1,
            format: "extended",
            ...t
         };
         let r = this.shiftTo("hours", "minutes", "seconds", "milliseconds"),
            n = t.format === "basic" ? "hhmm" : "hh:mm";
         (!t.suppressSeconds || r.seconds !== 0 || r.milliseconds !== 0) && (n += t.format === "basic" ? "ss" : ":ss", (!t.suppressMilliseconds || r.milliseconds !== 0) && (n += ".SSS"));
         let i = r.toFormat(n);
         return t.includePrefix && (i = "T" + i), i
      }
      toJSON() {
         return this.toISO()
      }
      toString() {
         return this.toISO()
      }
      toMillis() {
         return this.as("milliseconds")
      }
      valueOf() {
         return this.toMillis()
      }
      plus(t) {
         if (!this.isValid) return this;
         let a = e.fromDurationLike(t),
            r = {};
         for (let n of xr)(tr(a.values, n) || tr(this.values, n)) && (r[n] = a.get(n) + this.get(n));
         return ar(this, {
            values: r
         }, !0)
      }
      minus(t) {
         if (!this.isValid) return this;
         let a = e.fromDurationLike(t);
         return this.plus(a.negate())
      }
      mapUnits(t) {
         if (!this.isValid) return this;
         let a = {};
         for (let r of Object.keys(this.values)) a[r] = Di(t(this.values[r], r));
         return ar(this, {
            values: a
         }, !0)
      }
      get(t) {
         return this[e.normalizeUnit(t)]
      }
      set(t) {
         if (!this.isValid) return this;
         let a = {
            ...this.values,
            ...qr(t, e.normalizeUnit)
         };
         return ar(this, {
            values: a
         })
      }
      reconfigure({
         locale: t,
         numberingSystem: a,
         conversionAccuracy: r,
         matrix: n
      } = {}) {
         let s = {
            loc: this.loc.clone({
               locale: t,
               numberingSystem: a
            }),
            matrix: n,
            conversionAccuracy: r
         };
         return ar(this, s)
      }
      as(t) {
         return this.isValid ? this.shiftTo(t).get(t) : NaN
      }
      normalize() {
         if (!this.isValid) return this;
         let t = this.toObject();
         return Qf(this.matrix, t), ar(this, {
            values: t
         }, !0)
      }
      rescale() {
         if (!this.isValid) return this;
         let t = $f(this.normalize().shiftToAll().toObject());
         return ar(this, {
            values: t
         }, !0)
      }
      shiftTo(...t) {
         if (!this.isValid) return this;
         if (t.length === 0) return this;
         t = t.map(s => e.normalizeUnit(s));
         let a = {},
            r = {},
            n = this.toObject(),
            i;
         for (let s of xr)
            if (t.indexOf(s) >= 0) {
               i = s;
               let o = 0;
               for (let l in r) o += this.matrix[l][s] * r[l], r[l] = 0;
               _t(n[s]) && (o += n[s]);
               let u = Math.trunc(o);
               a[s] = u, r[s] = (o * 1e3 - u * 1e3) / 1e3;
               for (let l in n) xr.indexOf(l) > xr.indexOf(s) && Mo(this.matrix, n, l, a, s)
            } else _t(n[s]) && (r[s] = n[s]);
         for (let s in r) r[s] !== 0 && (a[i] += s === i ? r[s] : r[s] / this.matrix[i][s]);
         return ar(this, {
            values: a
         }, !0).normalize()
      }
      shiftToAll() {
         return this.isValid ? this.shiftTo("years", "months", "weeks", "days", "hours", "minutes", "seconds", "milliseconds") : this
      }
      negate() {
         if (!this.isValid) return this;
         let t = {};
         for (let a of Object.keys(this.values)) t[a] = this.values[a] === 0 ? 0 : -this.values[a];
         return ar(this, {
            values: t
         }, !0)
      }
      get years() {
         return this.isValid ? this.values.years || 0 : NaN
      }
      get quarters() {
         return this.isValid ? this.values.quarters || 0 : NaN
      }
      get months() {
         return this.isValid ? this.values.months || 0 : NaN
      }
      get weeks() {
         return this.isValid ? this.values.weeks || 0 : NaN
      }
      get days() {
         return this.isValid ? this.values.days || 0 : NaN
      }
      get hours() {
         return this.isValid ? this.values.hours || 0 : NaN
      }
      get minutes() {
         return this.isValid ? this.values.minutes || 0 : NaN
      }
      get seconds() {
         return this.isValid ? this.values.seconds || 0 : NaN
      }
      get milliseconds() {
         return this.isValid ? this.values.milliseconds || 0 : NaN
      }
      get isValid() {
         return this.invalid === null
      }
      get invalidReason() {
         return this.invalid ? this.invalid.reason : null
      }
      get invalidExplanation() {
         return this.invalid ? this.invalid.explanation : null
      }
      equals(t) {
         if (!this.isValid || !t.isValid || !this.loc.equals(t.loc)) return !1;

         function a(r, n) {
            return r === void 0 || r === 0 ? n === void 0 || n === 0 : r === n
         }
         for (let r of xr)
            if (!a(this.values[r], t.values[r])) return !1;
         return !0
      }
   };
   var Qr = "Invalid Interval";

   function jf(e, t) {
      return !e || !e.isValid ? zt.invalid("missing or invalid start") : !t || !t.isValid ? zt.invalid("missing or invalid end") : t < e ? zt.invalid("end before start", `The end of an interval must be after its start, but you had start=${e.toISO()} and end=${t.toISO()}`) : null
   }
   var zt = class e {
      constructor(t) {
         this.s = t.start, this.e = t.end, this.invalid = t.invalid || null, this.isLuxonInterval = !0
      }
      static invalid(t, a = null) {
         if (!t) throw new Ne("need to specify a reason the Interval is invalid");
         let r = t instanceof Re ? t : new Re(t, a);
         if (ue.throwOnInvalid) throw new En(r);
         return new e({
            invalid: r
         })
      }
      static fromDateTimes(t, a) {
         let r = $r(t),
            n = $r(a),
            i = jf(r, n);
         return i ?? new e({
            start: r,
            end: n
         })
      }
      static after(t, a) {
         let r = Te.fromDurationLike(a),
            n = $r(t);
         return e.fromDateTimes(n, n.plus(r))
      }
      static before(t, a) {
         let r = Te.fromDurationLike(a),
            n = $r(t);
         return e.fromDateTimes(n.minus(r), n)
      }
      static fromISO(t, a) {
         let [r, n] = (t || "").split("/", 2);
         if (r && n) {
            let i, s;
            try {
               i = ie.fromISO(r, a), s = i.isValid
            } catch {
               s = !1
            }
            let o, u;
            try {
               o = ie.fromISO(n, a), u = o.isValid
            } catch {
               u = !1
            }
            if (s && u) return e.fromDateTimes(i, o);
            if (s) {
               let l = Te.fromISO(n, a);
               if (l.isValid) return e.after(i, l)
            } else if (u) {
               let l = Te.fromISO(r, a);
               if (l.isValid) return e.before(o, l)
            }
         }
         return e.invalid("unparsable", `the input "${t}" can't be parsed as ISO 8601`)
      }
      static isInterval(t) {
         return t && t.isLuxonInterval || !1
      }
      get start() {
         return this.isValid ? this.s : null
      }
      get end() {
         return this.isValid ? this.e : null
      }
      get isValid() {
         return this.invalidReason === null
      }
      get invalidReason() {
         return this.invalid ? this.invalid.reason : null
      }
      get invalidExplanation() {
         return this.invalid ? this.invalid.explanation : null
      }
      length(t = "milliseconds") {
         return this.isValid ? this.toDuration(t).get(t) : NaN
      }
      count(t = "milliseconds") {
         if (!this.isValid) return NaN;
         let a = this.start.startOf(t),
            r = this.end.startOf(t);
         return Math.floor(r.diff(a, t).get(t)) + (r.valueOf() !== this.end.valueOf())
      }
      hasSame(t) {
         return this.isValid ? this.isEmpty() || this.e.minus(1).hasSame(this.s, t) : !1
      }
      isEmpty() {
         return this.s.valueOf() === this.e.valueOf()
      }
      isAfter(t) {
         return this.isValid ? this.s > t : !1
      }
      isBefore(t) {
         return this.isValid ? this.e <= t : !1
      }
      contains(t) {
         return this.isValid ? this.s <= t && this.e > t : !1
      }
      set({
         start: t,
         end: a
      } = {}) {
         return this.isValid ? e.fromDateTimes(t || this.s, a || this.e) : this
      }
      splitAt(...t) {
         if (!this.isValid) return [];
         let a = t.map($r).filter(s => this.contains(s)).sort(),
            r = [],
            {
               s: n
            } = this,
            i = 0;
         for (; n < this.e;) {
            let s = a[i] || this.e,
               o = +s > +this.e ? this.e : s;
            r.push(e.fromDateTimes(n, o)), n = o, i += 1
         }
         return r
      }
      splitBy(t) {
         let a = Te.fromDurationLike(t);
         if (!this.isValid || !a.isValid || a.as("milliseconds") === 0) return [];
         let {
            s: r
         } = this, n = 1, i, s = [];
         for (; r < this.e;) {
            let o = this.start.plus(a.mapUnits(u => u * n));
            i = +o > +this.e ? this.e : o, s.push(e.fromDateTimes(r, i)), r = i, n += 1
         }
         return s
      }
      divideEqually(t) {
         return this.isValid ? this.splitBy(this.length() / t).slice(0, t) : []
      }
      overlaps(t) {
         return this.e > t.s && this.s < t.e
      }
      abutsStart(t) {
         return this.isValid ? +this.e == +t.s : !1
      }
      abutsEnd(t) {
         return this.isValid ? +t.e == +this.s : !1
      }
      engulfs(t) {
         return this.isValid ? this.s <= t.s && this.e >= t.e : !1
      }
      equals(t) {
         return !this.isValid || !t.isValid ? !1 : this.s.equals(t.s) && this.e.equals(t.e)
      }
      intersection(t) {
         if (!this.isValid) return this;
         let a = this.s > t.s ? this.s : t.s,
            r = this.e < t.e ? this.e : t.e;
         return a >= r ? null : e.fromDateTimes(a, r)
      }
      union(t) {
         if (!this.isValid) return this;
         let a = this.s < t.s ? this.s : t.s,
            r = this.e > t.e ? this.e : t.e;
         return e.fromDateTimes(a, r)
      }
      static merge(t) {
         let [a, r] = t.sort((n, i) => n.s - i.s).reduce(([n, i], s) => i ? i.overlaps(s) || i.abutsStart(s) ? [n, i.union(s)] : [n.concat([i]), s] : [n, s], [
            [], null
         ]);
         return r && a.push(r), a
      }
      static xor(t) {
         let a = null,
            r = 0,
            n = [],
            i = t.map(u => [{
               time: u.s,
               type: "s"
            }, {
               time: u.e,
               type: "e"
            }]),
            s = Array.prototype.concat(...i),
            o = s.sort((u, l) => u.time - l.time);
         for (let u of o) r += u.type === "s" ? 1 : -1, r === 1 ? a = u.time : (a && +a != +u.time && n.push(e.fromDateTimes(a, u.time)), a = null);
         return e.merge(n)
      }
      difference(...t) {
         return e.xor([this].concat(t)).map(a => this.intersection(a)).filter(a => a && !a.isEmpty())
      }
      toString() {
         return this.isValid ? `[${this.s.toISO()} \u2013 ${this.e.toISO()})` : Qr
      }
      toLocaleString(t = Xt, a = {}) {
         return this.isValid ? De.create(this.s.loc.clone(a), t).formatInterval(this) : Qr
      }
      toISO(t) {
         return this.isValid ? `${this.s.toISO(t)}/${this.e.toISO(t)}` : Qr
      }
      toISODate() {
         return this.isValid ? `${this.s.toISODate()}/${this.e.toISODate()}` : Qr
      }
      toISOTime(t) {
         return this.isValid ? `${this.s.toISOTime(t)}/${this.e.toISOTime(t)}` : Qr
      }
      toFormat(t, {
         separator: a = " \u2013 "
      } = {}) {
         return this.isValid ? `${this.s.toFormat(t)}${a}${this.e.toFormat(t)}` : Qr
      }
      toDuration(t, a) {
         return this.isValid ? this.e.diff(this.s, t, a) : Te.invalid(this.invalidReason)
      }
      mapEndpoints(t) {
         return e.fromDateTimes(t(this.s), t(this.e))
      }
   };
   var Wt = class {
      static hasDST(t = ue.defaultZone) {
         let a = ie.now().setZone(t).set({
            month: 12
         });
         return !t.isUniversal && a.offset !== a.set({
            month: 6
         }).offset
      }
      static isValidIANAZone(t) {
         return Je.isValidZone(t)
      }
      static normalizeZone(t) {
         return bt(t, ue.defaultZone)
      }
      static months(t = "long", {
         locale: a = null,
         numberingSystem: r = null,
         locObj: n = null,
         outputCalendar: i = "gregory"
      } = {}) {
         return (n || he.create(a, r, i)).months(t)
      }
      static monthsFormat(t = "long", {
         locale: a = null,
         numberingSystem: r = null,
         locObj: n = null,
         outputCalendar: i = "gregory"
      } = {}) {
         return (n || he.create(a, r, i)).months(t, !0)
      }
      static weekdays(t = "long", {
         locale: a = null,
         numberingSystem: r = null,
         locObj: n = null
      } = {}) {
         return (n || he.create(a, r, null)).weekdays(t)
      }
      static weekdaysFormat(t = "long", {
         locale: a = null,
         numberingSystem: r = null,
         locObj: n = null
      } = {}) {
         return (n || he.create(a, r, null)).weekdays(t, !0)
      }
      static meridiems({
         locale: t = null
      } = {}) {
         return he.create(t).meridiems()
      }
      static eras(t = "short", {
         locale: a = null
      } = {}) {
         return he.create(a, null, "gregory").eras(t)
      }
      static features() {
         return {
            relative: An()
         }
      }
   };

   function Ko(e, t) {
      let a = n => n.toUTC(0, {
            keepLocalTime: !0
         }).startOf("day").valueOf(),
         r = a(t) - a(e);
      return Math.floor(Te.fromMillis(r).as("days"))
   }

   function Xf(e, t, a) {
      let r = [
            ["years", (u, l) => l.year - u.year],
            ["quarters", (u, l) => l.quarter - u.quarter + (l.year - u.year) * 4],
            ["months", (u, l) => l.month - u.month + (l.year - u.year) * 12],
            ["weeks", (u, l) => {
               let c = Ko(u, l);
               return (c - c % 7) / 7
            }],
            ["days", Ko]
         ],
         n = {},
         i = e,
         s, o;
      for (let [u, l] of r) a.indexOf(u) >= 0 && (s = u, n[u] = l(e, t), o = i.plus(n), o > t ? (n[u]--, e = i.plus(n)) : e = o);
      return [e, n, o, s]
   }

   function qo(e, t, a, r) {
      let [n, i, s, o] = Xf(e, t, a), u = t - n, l = a.filter(f => ["hours", "minutes", "seconds", "milliseconds"].indexOf(f) >= 0);
      l.length === 0 && (s < t && (s = n.plus({
         [o]: 1
      })), s !== n && (i[o] = (i[o] || 0) + u / (s - n)));
      let c = Te.fromObject(i, r);
      return l.length > 0 ? Te.fromMillis(u, r).shiftTo(...l).plus(c) : c
   }
   var Pi = {
         arab: "[\u0660-\u0669]",
         arabext: "[\u06F0-\u06F9]",
         bali: "[\u1B50-\u1B59]",
         beng: "[\u09E6-\u09EF]",
         deva: "[\u0966-\u096F]",
         fullwide: "[\uFF10-\uFF19]",
         gujr: "[\u0AE6-\u0AEF]",
         hanidec: "[\u3007|\u4E00|\u4E8C|\u4E09|\u56DB|\u4E94|\u516D|\u4E03|\u516B|\u4E5D]",
         khmr: "[\u17E0-\u17E9]",
         knda: "[\u0CE6-\u0CEF]",
         laoo: "[\u0ED0-\u0ED9]",
         limb: "[\u1946-\u194F]",
         mlym: "[\u0D66-\u0D6F]",
         mong: "[\u1810-\u1819]",
         mymr: "[\u1040-\u1049]",
         orya: "[\u0B66-\u0B6F]",
         tamldec: "[\u0BE6-\u0BEF]",
         telu: "[\u0C66-\u0C6F]",
         thai: "[\u0E50-\u0E59]",
         tibt: "[\u0F20-\u0F29]",
         latn: "\\d"
      },
      Ho = {
         arab: [1632, 1641],
         arabext: [1776, 1785],
         bali: [6992, 7001],
         beng: [2534, 2543],
         deva: [2406, 2415],
         fullwide: [65296, 65303],
         gujr: [2790, 2799],
         khmr: [6112, 6121],
         knda: [3302, 3311],
         laoo: [3792, 3801],
         limb: [6470, 6479],
         mlym: [3430, 3439],
         mong: [6160, 6169],
         mymr: [4160, 4169],
         orya: [2918, 2927],
         tamldec: [3046, 3055],
         telu: [3174, 3183],
         thai: [3664, 3673],
         tibt: [3872, 3881]
      },
      Jf = Pi.hanidec.replace(/[\[|\]]/g, "").split("");

   function Go(e) {
      let t = parseInt(e, 10);
      if (isNaN(t)) {
         t = "";
         for (let a = 0; a < e.length; a++) {
            let r = e.charCodeAt(a);
            if (e[a].search(Pi.hanidec) !== -1) t += Jf.indexOf(e[a]);
            else
               for (let n in Ho) {
                  let [i, s] = Ho[n];
                  r >= i && r <= s && (t += r - i)
               }
         }
         return parseInt(t, 10)
      } else return t
   }

   function pt({
      numberingSystem: e
   }, t = "") {
      return new RegExp(`${Pi[e||"latn"]}${t}`)
   }
   var e0 = "missing Intl.DateTimeFormat.formatToParts support";

   function se(e, t = a => a) {
      return {
         regex: e,
         deser: ([a]) => t(Go(a))
      }
   }
   var t0 = String.fromCharCode(160),
      Yo = `[ ${t0}]`,
      Zo = new RegExp(Yo, "g");

   function r0(e) {
      return e.replace(/\./g, "\\.?").replace(Zo, Yo)
   }

   function zo(e) {
      return e.replace(/\./g, "").replace(Zo, " ").toLowerCase()
   }

   function At(e, t) {
      return e === null ? null : {
         regex: RegExp(e.map(r0).join("|")),
         deser: ([a]) => e.findIndex(r => zo(a) === zo(r)) + t
      }
   }

   function Wo(e, t) {
      return {
         regex: e,
         deser: ([, a, r]) => vr(a, r),
         groups: t
      }
   }

   function Bn(e) {
      return {
         regex: e,
         deser: ([t]) => t
      }
   }

   function a0(e) {
      return e.replace(/[\-\[\]{}()*+?.,\\\^$|#\s]/g, "\\$&")
   }

   function n0(e, t) {
      let a = pt(t),
         r = pt(t, "{2}"),
         n = pt(t, "{3}"),
         i = pt(t, "{4}"),
         s = pt(t, "{6}"),
         o = pt(t, "{1,2}"),
         u = pt(t, "{1,3}"),
         l = pt(t, "{1,6}"),
         c = pt(t, "{1,9}"),
         f = pt(t, "{2,4}"),
         y = pt(t, "{4,6}"),
         g = T => ({
            regex: RegExp(a0(T.val)),
            deser: ([I]) => I,
            literal: !0
         }),
         x = (T => {
            if (e.literal) return g(T);
            switch (T.val) {
               case "G":
                  return At(t.eras("short", !1), 0);
               case "GG":
                  return At(t.eras("long", !1), 0);
               case "y":
                  return se(l);
               case "yy":
                  return se(f, Ha);
               case "yyyy":
                  return se(i);
               case "yyyyy":
                  return se(y);
               case "yyyyyy":
                  return se(s);
               case "M":
                  return se(o);
               case "MM":
                  return se(r);
               case "MMM":
                  return At(t.months("short", !0, !1), 1);
               case "MMMM":
                  return At(t.months("long", !0, !1), 1);
               case "L":
                  return se(o);
               case "LL":
                  return se(r);
               case "LLL":
                  return At(t.months("short", !1, !1), 1);
               case "LLLL":
                  return At(t.months("long", !1, !1), 1);
               case "d":
                  return se(o);
               case "dd":
                  return se(r);
               case "o":
                  return se(u);
               case "ooo":
                  return se(n);
               case "HH":
                  return se(r);
               case "H":
                  return se(o);
               case "hh":
                  return se(r);
               case "h":
                  return se(o);
               case "mm":
                  return se(r);
               case "m":
                  return se(o);
               case "q":
                  return se(o);
               case "qq":
                  return se(r);
               case "s":
                  return se(o);
               case "ss":
                  return se(r);
               case "S":
                  return se(u);
               case "SSS":
                  return se(n);
               case "u":
                  return Bn(c);
               case "uu":
                  return Bn(o);
               case "uuu":
                  return se(a);
               case "a":
                  return At(t.meridiems(), 0);
               case "kkkk":
                  return se(i);
               case "kk":
                  return se(f, Ha);
               case "W":
                  return se(o);
               case "WW":
                  return se(r);
               case "E":
               case "c":
                  return se(a);
               case "EEE":
                  return At(t.weekdays("short", !1, !1), 1);
               case "EEEE":
                  return At(t.weekdays("long", !1, !1), 1);
               case "ccc":
                  return At(t.weekdays("short", !0, !1), 1);
               case "cccc":
                  return At(t.weekdays("long", !0, !1), 1);
               case "Z":
               case "ZZ":
                  return Wo(new RegExp(`([+-]${o.source})(?::(${r.source}))?`), 2);
               case "ZZZ":
                  return Wo(new RegExp(`([+-]${o.source})(${r.source})?`), 2);
               case "z":
                  return Bn(/[a-z_+-/]{1,256}?/i);
               case " ":
                  return Bn(/[^\S\n\r]/);
               default:
                  return g(T)
            }
         })(e) || {
            invalidReason: e0
         };
      return x.token = e, x
   }
   var i0 = {
      year: {
         "2-digit": "yy",
         numeric: "yyyyy"
      },
      month: {
         numeric: "M",
         "2-digit": "MM",
         short: "MMM",
         long: "MMMM"
      },
      day: {
         numeric: "d",
         "2-digit": "dd"
      },
      weekday: {
         short: "EEE",
         long: "EEEE"
      },
      dayperiod: "a",
      dayPeriod: "a",
      hour: {
         numeric: "h",
         "2-digit": "hh"
      },
      minute: {
         numeric: "m",
         "2-digit": "mm"
      },
      second: {
         numeric: "s",
         "2-digit": "ss"
      },
      timeZoneName: {
         long: "ZZZZZ",
         short: "ZZZ"
      }
   };

   function s0(e, t) {
      let {
         type: a,
         value: r
      } = e;
      if (a === "literal") {
         let s = /^\s+$/.test(r);
         return {
            literal: !s,
            val: s ? " " : r
         }
      }
      let n = t[a],
         i = i0[a];
      if (typeof i == "object" && (i = i[n]), i) return {
         literal: !1,
         val: i
      }
   }

   function o0(e) {
      return [`^${e.map(a=>a.regex).reduce((a,r)=>`${a}(${r.source})`,"")}$`, e]
   }

   function u0(e, t, a) {
      let r = e.match(t);
      if (r) {
         let n = {},
            i = 1;
         for (let s in a)
            if (tr(a, s)) {
               let o = a[s],
                  u = o.groups ? o.groups + 1 : 1;
               !o.literal && o.token && (n[o.token.val[0]] = o.deser(r.slice(i, i + u))), i += u
            } return [r, n]
      } else return [r, {}]
   }

   function l0(e) {
      let t = i => {
            switch (i) {
               case "S":
                  return "millisecond";
               case "s":
                  return "second";
               case "m":
                  return "minute";
               case "h":
               case "H":
                  return "hour";
               case "d":
                  return "day";
               case "o":
                  return "ordinal";
               case "L":
               case "M":
                  return "month";
               case "y":
                  return "year";
               case "E":
               case "c":
                  return "weekday";
               case "W":
                  return "weekNumber";
               case "k":
                  return "weekYear";
               case "q":
                  return "quarter";
               default:
                  return null
            }
         },
         a = null,
         r;
      return Q(e.z) || (a = Je.create(e.z)), Q(e.Z) || (a || (a = new _e(e.Z)), r = e.Z), Q(e.q) || (e.M = (e.q - 1) * 3 + 1), Q(e.h) || (e.h < 12 && e.a === 1 ? e.h += 12 : e.h === 12 && e.a === 0 && (e.h = 0)), e.G === 0 && e.y && (e.y = -e.y), Q(e.u) || (e.S = qa(e.u)), [Object.keys(e).reduce((i, s) => {
         let o = t(s);
         return o && (i[o] = e[s]), i
      }, {}), a, r]
   }
   var Vi = null;

   function c0() {
      return Vi || (Vi = ie.fromMillis(1555555555555)), Vi
   }

   function f0(e, t) {
      if (e.literal) return e;
      let a = De.macroTokenToFormatOpts(e.val),
         r = qi(a, t);
      return r == null || r.includes(void 0) ? e : r
   }

   function Mi(e, t) {
      return Array.prototype.concat(...e.map(a => f0(a, t)))
   }

   function Ki(e, t, a) {
      let r = Mi(De.parseFormat(a), e),
         n = r.map(s => n0(s, e)),
         i = n.find(s => s.invalidReason);
      if (i) return {
         input: t,
         tokens: r,
         invalidReason: i.invalidReason
      };
      {
         let [s, o] = o0(n), u = RegExp(s, "i"), [l, c] = u0(t, u, o), [f, y, g] = c ? l0(c) : [null, null, void 0];
         if (tr(c, "a") && tr(c, "H")) throw new Ht("Can't include meridiem when specifying 24-hour format");
         return {
            input: t,
            tokens: r,
            regex: u,
            rawMatches: l,
            matches: c,
            result: f,
            zone: y,
            specificOffset: g
         }
      }
   }

   function Qo(e, t, a) {
      let {
         result: r,
         zone: n,
         specificOffset: i,
         invalidReason: s
      } = Ki(e, t, a);
      return [r, n, i, s]
   }

   function qi(e, t) {
      return e ? De.create(t, e).formatDateTimeParts(c0()).map(n => s0(n, e)) : null
   }
   var $o = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334],
      jo = [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335];

   function yt(e, t) {
      return new Re("unit out of range", `you specified ${t} (of type ${typeof t}) as a ${e}, which is invalid`)
   }

   function Xo(e, t, a) {
      let r = new Date(Date.UTC(e, t - 1, a));
      e < 100 && e >= 0 && r.setUTCFullYear(r.getUTCFullYear() - 1900);
      let n = r.getUTCDay();
      return n === 0 ? 7 : n
   }

   function Jo(e, t, a) {
      return a + (Er(e) ? jo : $o)[t - 1]
   }

   function eu(e, t) {
      let a = Er(e) ? jo : $o,
         r = a.findIndex(i => i < t),
         n = t - a[r];
      return {
         month: r + 1,
         day: n
      }
   }

   function wn(e) {
      let {
         year: t,
         month: a,
         day: r
      } = e, n = Jo(t, a, r), i = Xo(t, a, r), s = Math.floor((n - i + 10) / 7), o;
      return s < 1 ? (o = t - 1, s = Kr(o)) : s > Kr(t) ? (o = t + 1, s = 1) : o = t, {
         weekYear: o,
         weekNumber: s,
         weekday: i,
         ...Ga(e)
      }
   }

   function Hi(e) {
      let {
         weekYear: t,
         weekNumber: a,
         weekday: r
      } = e, n = Xo(t, 1, 4), i = Cr(t), s = a * 7 + r - n - 3, o;
      s < 1 ? (o = t - 1, s += Cr(o)) : s > i ? (o = t + 1, s -= Cr(t)) : o = t;
      let {
         month: u,
         day: l
      } = eu(o, s);
      return {
         year: o,
         month: u,
         day: l,
         ...Ga(e)
      }
   }

   function Nn(e) {
      let {
         year: t,
         month: a,
         day: r
      } = e, n = Jo(t, a, r);
      return {
         year: t,
         ordinal: n,
         ...Ga(e)
      }
   }

   function Gi(e) {
      let {
         year: t,
         ordinal: a
      } = e, {
         month: r,
         day: n
      } = eu(t, a);
      return {
         year: t,
         month: r,
         day: n,
         ...Ga(e)
      }
   }

   function tu(e) {
      let t = Ka(e.weekYear),
         a = Dt(e.weekNumber, 1, Kr(e.weekYear)),
         r = Dt(e.weekday, 1, 7);
      return t ? a ? r ? !1 : yt("weekday", e.weekday) : yt("week", e.week) : yt("weekYear", e.weekYear)
   }

   function ru(e) {
      let t = Ka(e.year),
         a = Dt(e.ordinal, 1, Cr(e.year));
      return t ? a ? !1 : yt("ordinal", e.ordinal) : yt("year", e.year)
   }

   function zi(e) {
      let t = Ka(e.year),
         a = Dt(e.month, 1, 12),
         r = Dt(e.day, 1, Mr(e.year, e.month));
      return t ? a ? r ? !1 : yt("day", e.day) : yt("month", e.month) : yt("year", e.year)
   }

   function Wi(e) {
      let {
         hour: t,
         minute: a,
         second: r,
         millisecond: n
      } = e, i = Dt(t, 0, 23) || t === 24 && a === 0 && r === 0 && n === 0, s = Dt(a, 0, 59), o = Dt(r, 0, 59), u = Dt(n, 0, 999);
      return i ? s ? o ? u ? !1 : yt("millisecond", n) : yt("second", r) : yt("minute", a) : yt("hour", t)
   }
   var Yi = "Invalid DateTime",
      au = 864e13;

   function _n(e) {
      return new Re("unsupported zone", `the zone "${e.name}" is not supported`)
   }

   function Zi(e) {
      return e.weekData === null && (e.weekData = wn(e.c)), e.weekData
   }

   function Ya(e, t) {
      let a = {
         ts: e.ts,
         zone: e.zone,
         c: e.c,
         o: e.o,
         loc: e.loc,
         invalid: e.invalid
      };
      return new ie({
         ...a,
         ...t,
         old: a
      })
   }

   function fu(e, t, a) {
      let r = e - t * 60 * 1e3,
         n = a.offset(r);
      if (t === n) return [r, t];
      r -= (n - t) * 60 * 1e3;
      let i = a.offset(r);
      return n === i ? [r, n] : [e - Math.min(n, i) * 60 * 1e3, Math.max(n, i)]
   }

   function nu(e, t) {
      e += t * 60 * 1e3;
      let a = new Date(e);
      return {
         year: a.getUTCFullYear(),
         month: a.getUTCMonth() + 1,
         day: a.getUTCDate(),
         hour: a.getUTCHours(),
         minute: a.getUTCMinutes(),
         second: a.getUTCSeconds(),
         millisecond: a.getUTCMilliseconds()
      }
   }

   function Rn(e, t, a) {
      return fu(Va(e), t, a)
   }

   function iu(e, t) {
      let a = e.o,
         r = e.c.year + Math.trunc(t.years),
         n = e.c.month + Math.trunc(t.months) + Math.trunc(t.quarters) * 3,
         i = {
            ...e.c,
            year: r,
            month: n,
            day: Math.min(e.c.day, Mr(r, n)) + Math.trunc(t.days) + Math.trunc(t.weeks) * 7
         },
         s = Te.fromObject({
            years: t.years - Math.trunc(t.years),
            quarters: t.quarters - Math.trunc(t.quarters),
            months: t.months - Math.trunc(t.months),
            weeks: t.weeks - Math.trunc(t.weeks),
            days: t.days - Math.trunc(t.days),
            hours: t.hours,
            minutes: t.minutes,
            seconds: t.seconds,
            milliseconds: t.milliseconds
         }).as("milliseconds"),
         o = Va(i),
         [u, l] = fu(o, a, e.zone);
      return s !== 0 && (u += s, l = e.zone.offset(u)), {
         ts: u,
         o: l
      }
   }

   function Za(e, t, a, r, n, i) {
      let {
         setZone: s,
         zone: o
      } = a;
      if (e && Object.keys(e).length !== 0 || t) {
         let u = t || o,
            l = ie.fromObject(e, {
               ...a,
               zone: u,
               specificOffset: i
            });
         return s ? l : l.setZone(o)
      } else return ie.invalid(new Re("unparsable", `the input "${n}" can't be parsed as ${r}`))
   }

   function Dn(e, t, a = !0) {
      return e.isValid ? De.create(he.create("en-US"), {
         allowZ: a,
         forceSimple: !0
      }).formatDateTimeFromString(e, t) : null
   }

   function Qi(e, t) {
      let a = e.c.year > 9999 || e.c.year < 0,
         r = "";
      return a && e.c.year >= 0 && (r += "+"), r += xe(e.c.year, a ? 6 : 4), t ? (r += "-", r += xe(e.c.month), r += "-", r += xe(e.c.day)) : (r += xe(e.c.month), r += xe(e.c.day)), r
   }

   function su(e, t, a, r, n, i) {
      let s = xe(e.c.hour);
      return t ? (s += ":", s += xe(e.c.minute), (e.c.second !== 0 || !a) && (s += ":")) : s += xe(e.c.minute), (e.c.second !== 0 || !a) && (s += xe(e.c.second), (e.c.millisecond !== 0 || !r) && (s += ".", s += xe(e.c.millisecond, 3))), n && (e.isOffsetFixed && e.offset === 0 && !i ? s += "Z" : e.o < 0 ? (s += "-", s += xe(Math.trunc(-e.o / 60)), s += ":", s += xe(Math.trunc(-e.o % 60))) : (s += "+", s += xe(Math.trunc(e.o / 60)), s += ":", s += xe(Math.trunc(e.o % 60)))), i && (s += "[" + e.zone.ianaName + "]"), s
   }
   var hu = {
         month: 1,
         day: 1,
         hour: 0,
         minute: 0,
         second: 0,
         millisecond: 0
      },
      h0 = {
         weekNumber: 1,
         weekday: 1,
         hour: 0,
         minute: 0,
         second: 0,
         millisecond: 0
      },
      d0 = {
         ordinal: 1,
         hour: 0,
         minute: 0,
         second: 0,
         millisecond: 0
      },
      du = ["year", "month", "day", "hour", "minute", "second", "millisecond"],
      p0 = ["weekYear", "weekNumber", "weekday", "hour", "minute", "second", "millisecond"],
      y0 = ["year", "ordinal", "hour", "minute", "second", "millisecond"];

   function ou(e) {
      let t = {
         year: "year",
         years: "year",
         month: "month",
         months: "month",
         day: "day",
         days: "day",
         hour: "hour",
         hours: "hour",
         minute: "minute",
         minutes: "minute",
         quarter: "quarter",
         quarters: "quarter",
         second: "second",
         seconds: "second",
         millisecond: "millisecond",
         milliseconds: "millisecond",
         weekday: "weekday",
         weekdays: "weekday",
         weeknumber: "weekNumber",
         weeksnumber: "weekNumber",
         weeknumbers: "weekNumber",
         weekyear: "weekYear",
         weekyears: "weekYear",
         ordinal: "ordinal"
      } [e.toLowerCase()];
      if (!t) throw new Fr(e);
      return t
   }

   function uu(e, t) {
      let a = bt(t.zone, ue.defaultZone),
         r = he.fromObject(t),
         n = ue.now(),
         i, s;
      if (Q(e.year)) i = n;
      else {
         for (let l of du) Q(e[l]) && (e[l] = hu[l]);
         let o = zi(e) || Wi(e);
         if (o) return ie.invalid(o);
         let u = a.offset(n);
         [i, s] = Rn(e, u, a)
      }
      return new ie({
         ts: i,
         zone: a,
         loc: r,
         o: s
      })
   }

   function lu(e, t, a) {
      let r = Q(a.round) ? !0 : a.round,
         n = (s, o) => (s = Pr(s, r || a.calendary ? 0 : 2, !0), t.loc.clone(a).relFormatter(a).format(s, o)),
         i = s => a.calendary ? t.hasSame(e, s) ? 0 : t.startOf(s).diff(e.startOf(s), s).get(s) : t.diff(e, s).get(s);
      if (a.unit) return n(i(a.unit), a.unit);
      for (let s of a.units) {
         let o = i(s);
         if (Math.abs(o) >= 1) return n(o, s)
      }
      return n(e > t ? -0 : 0, a.units[a.units.length - 1])
   }

   function cu(e) {
      let t = {},
         a;
      return e.length > 0 && typeof e[e.length - 1] == "object" ? (t = e[e.length - 1], a = Array.from(e).slice(0, e.length - 1)) : a = Array.from(e), [t, a]
   }
   var ie = class e {
      constructor(t) {
         let a = t.zone || ue.defaultZone,
            r = t.invalid || (Number.isNaN(t.ts) ? new Re("invalid input") : null) || (a.isValid ? null : _n(a));
         this.ts = Q(t.ts) ? ue.now() : t.ts;
         let n = null,
            i = null;
         if (!r)
            if (t.old && t.old.ts === this.ts && t.old.zone.equals(a))[n, i] = [t.old.c, t.old.o];
            else {
               let o = a.offset(this.ts);
               n = nu(this.ts, o), r = Number.isNaN(n.year) ? new Re("invalid input") : null, n = r ? null : n, i = r ? null : o
            } this._zone = a, this.loc = t.loc || he.create(), this.invalid = r, this.weekData = null, this.c = n, this.o = i, this.isLuxonDateTime = !0
      }
      static now() {
         return new e({})
      }
      static local() {
         let [t, a] = cu(arguments), [r, n, i, s, o, u, l] = a;
         return uu({
            year: r,
            month: n,
            day: i,
            hour: s,
            minute: o,
            second: u,
            millisecond: l
         }, t)
      }
      static utc() {
         let [t, a] = cu(arguments), [r, n, i, s, o, u, l] = a;
         return t.zone = _e.utcInstance, uu({
            year: r,
            month: n,
            day: i,
            hour: s,
            minute: o,
            second: u,
            millisecond: l
         }, t)
      }
      static fromJSDate(t, a = {}) {
         let r = vo(t) ? t.valueOf() : NaN;
         if (Number.isNaN(r)) return e.invalid("invalid input");
         let n = bt(a.zone, ue.defaultZone);
         return n.isValid ? new e({
            ts: r,
            zone: n,
            loc: he.fromObject(a)
         }) : e.invalid(_n(n))
      }
      static fromMillis(t, a = {}) {
         if (_t(t)) return t < -au || t > au ? e.invalid("Timestamp out of range") : new e({
            ts: t,
            zone: bt(a.zone, ue.defaultZone),
            loc: he.fromObject(a)
         });
         throw new Ne(`fromMillis requires a numerical input, but received a ${typeof t} with value ${t}`)
      }
      static fromSeconds(t, a = {}) {
         if (_t(t)) return new e({
            ts: t * 1e3,
            zone: bt(a.zone, ue.defaultZone),
            loc: he.fromObject(a)
         });
         throw new Ne("fromSeconds requires a numerical input")
      }
      static fromObject(t, a = {}) {
         t = t || {};
         let r = bt(a.zone, ue.defaultZone);
         if (!r.isValid) return e.invalid(_n(r));
         let n = ue.now(),
            i = Q(a.specificOffset) ? r.offset(n) : a.specificOffset,
            s = qr(t, ou),
            o = !Q(s.ordinal),
            u = !Q(s.year),
            l = !Q(s.month) || !Q(s.day),
            c = u || l,
            f = s.weekYear || s.weekNumber,
            y = he.fromObject(a);
         if ((c || o) && f) throw new Ht("Can't mix weekYear/weekNumber units with year/month/day or ordinals");
         if (l && o) throw new Ht("Can't mix ordinal dates with month/day");
         let g = f || s.weekday && !c,
            m, x, T = nu(n, i);
         g ? (m = p0, x = h0, T = wn(T)) : o ? (m = y0, x = d0, T = Nn(T)) : (m = du, x = hu);
         let I = !1;
         for (let z of m) {
            let oe = s[z];
            Q(oe) ? I ? s[z] = x[z] : s[z] = T[z] : I = !0
         }
         let A = g ? tu(s) : o ? ru(s) : zi(s),
            B = A || Wi(s);
         if (B) return e.invalid(B);
         let F = g ? Hi(s) : o ? Gi(s) : s,
            [R, D] = Rn(F, i, r),
            G = new e({
               ts: R,
               zone: r,
               o: D,
               loc: y
            });
         return s.weekday && c && t.weekday !== G.weekday ? e.invalid("mismatched weekday", `you can't specify both a weekday of ${s.weekday} and a date of ${G.toISO()}`) : G
      }
      static fromISO(t, a = {}) {
         let [r, n] = Lo(t);
         return Za(r, n, a, "ISO 8601", t)
      }
      static fromRFC2822(t, a = {}) {
         let [r, n] = ko(t);
         return Za(r, n, a, "RFC 2822", t)
      }
      static fromHTTP(t, a = {}) {
         let [r, n] = Oo(t);
         return Za(r, n, a, "HTTP", a)
      }
      static fromFormat(t, a, r = {}) {
         if (Q(t) || Q(a)) throw new Ne("fromFormat requires an input string and a format");
         let {
            locale: n = null,
            numberingSystem: i = null
         } = r, s = he.fromOpts({
            locale: n,
            numberingSystem: i,
            defaultToEN: !0
         }), [o, u, l, c] = Qo(s, t, a);
         return c ? e.invalid(c) : Za(o, u, r, `format ${a}`, t, l)
      }
      static fromString(t, a, r = {}) {
         return e.fromFormat(t, a, r)
      }
      static fromSQL(t, a = {}) {
         let [r, n] = Po(t);
         return Za(r, n, a, "SQL", t)
      }
      static invalid(t, a = null) {
         if (!t) throw new Ne("need to specify a reason the DateTime is invalid");
         let r = t instanceof Re ? t : new Re(t, a);
         if (ue.throwOnInvalid) throw new vn(r);
         return new e({
            invalid: r
         })
      }
      static isDateTime(t) {
         return t && t.isLuxonDateTime || !1
      }
      static parseFormatForOpts(t, a = {}) {
         let r = qi(t, he.fromObject(a));
         return r ? r.map(n => n ? n.val : null).join("") : null
      }
      static expandFormat(t, a = {}) {
         return Mi(De.parseFormat(t), he.fromObject(a)).map(n => n.val).join("")
      }
      get(t) {
         return this[t]
      }
      get isValid() {
         return this.invalid === null
      }
      get invalidReason() {
         return this.invalid ? this.invalid.reason : null
      }
      get invalidExplanation() {
         return this.invalid ? this.invalid.explanation : null
      }
      get locale() {
         return this.isValid ? this.loc.locale : null
      }
      get numberingSystem() {
         return this.isValid ? this.loc.numberingSystem : null
      }
      get outputCalendar() {
         return this.isValid ? this.loc.outputCalendar : null
      }
      get zone() {
         return this._zone
      }
      get zoneName() {
         return this.isValid ? this.zone.name : null
      }
      get year() {
         return this.isValid ? this.c.year : NaN
      }
      get quarter() {
         return this.isValid ? Math.ceil(this.c.month / 3) : NaN
      }
      get month() {
         return this.isValid ? this.c.month : NaN
      }
      get day() {
         return this.isValid ? this.c.day : NaN
      }
      get hour() {
         return this.isValid ? this.c.hour : NaN
      }
      get minute() {
         return this.isValid ? this.c.minute : NaN
      }
      get second() {
         return this.isValid ? this.c.second : NaN
      }
      get millisecond() {
         return this.isValid ? this.c.millisecond : NaN
      }
      get weekYear() {
         return this.isValid ? Zi(this).weekYear : NaN
      }
      get weekNumber() {
         return this.isValid ? Zi(this).weekNumber : NaN
      }
      get weekday() {
         return this.isValid ? Zi(this).weekday : NaN
      }
      get ordinal() {
         return this.isValid ? Nn(this.c).ordinal : NaN
      }
      get monthShort() {
         return this.isValid ? Wt.months("short", {
            locObj: this.loc
         })[this.month - 1] : null
      }
      get monthLong() {
         return this.isValid ? Wt.months("long", {
            locObj: this.loc
         })[this.month - 1] : null
      }
      get weekdayShort() {
         return this.isValid ? Wt.weekdays("short", {
            locObj: this.loc
         })[this.weekday - 1] : null
      }
      get weekdayLong() {
         return this.isValid ? Wt.weekdays("long", {
            locObj: this.loc
         })[this.weekday - 1] : null
      }
      get offset() {
         return this.isValid ? +this.o : NaN
      }
      get offsetNameShort() {
         return this.isValid ? this.zone.offsetName(this.ts, {
            format: "short",
            locale: this.locale
         }) : null
      }
      get offsetNameLong() {
         return this.isValid ? this.zone.offsetName(this.ts, {
            format: "long",
            locale: this.locale
         }) : null
      }
      get isOffsetFixed() {
         return this.isValid ? this.zone.isUniversal : null
      }
      get isInDST() {
         return this.isOffsetFixed ? !1 : this.offset > this.set({
            month: 1,
            day: 1
         }).offset || this.offset > this.set({
            month: 5
         }).offset
      }
      get isInLeapYear() {
         return Er(this.year)
      }
      get daysInMonth() {
         return Mr(this.year, this.month)
      }
      get daysInYear() {
         return this.isValid ? Cr(this.year) : NaN
      }
      get weeksInWeekYear() {
         return this.isValid ? Kr(this.weekYear) : NaN
      }
      resolvedLocaleOptions(t = {}) {
         let {
            locale: a,
            numberingSystem: r,
            calendar: n
         } = De.create(this.loc.clone(t), t).resolvedOptions(this);
         return {
            locale: a,
            numberingSystem: r,
            outputCalendar: n
         }
      }
      toUTC(t = 0, a = {}) {
         return this.setZone(_e.instance(t), a)
      }
      toLocal() {
         return this.setZone(ue.defaultZone)
      }
      setZone(t, {
         keepLocalTime: a = !1,
         keepCalendarTime: r = !1
      } = {}) {
         if (t = bt(t, ue.defaultZone), t.equals(this.zone)) return this;
         if (t.isValid) {
            let n = this.ts;
            if (a || r) {
               let i = t.offset(this.ts),
                  s = this.toObject();
               [n] = Rn(s, i, t)
            }
            return Ya(this, {
               ts: n,
               zone: t
            })
         } else return e.invalid(_n(t))
      }
      reconfigure({
         locale: t,
         numberingSystem: a,
         outputCalendar: r
      } = {}) {
         let n = this.loc.clone({
            locale: t,
            numberingSystem: a,
            outputCalendar: r
         });
         return Ya(this, {
            loc: n
         })
      }
      setLocale(t) {
         return this.reconfigure({
            locale: t
         })
      }
      set(t) {
         if (!this.isValid) return this;
         let a = qr(t, ou),
            r = !Q(a.weekYear) || !Q(a.weekNumber) || !Q(a.weekday),
            n = !Q(a.ordinal),
            i = !Q(a.year),
            s = !Q(a.month) || !Q(a.day),
            o = i || s,
            u = a.weekYear || a.weekNumber;
         if ((o || n) && u) throw new Ht("Can't mix weekYear/weekNumber units with year/month/day or ordinals");
         if (s && n) throw new Ht("Can't mix ordinal dates with month/day");
         let l;
         r ? l = Hi({
            ...wn(this.c),
            ...a
         }) : Q(a.ordinal) ? (l = {
            ...this.toObject(),
            ...a
         }, Q(a.day) && (l.day = Math.min(Mr(l.year, l.month), l.day))) : l = Gi({
            ...Nn(this.c),
            ...a
         });
         let [c, f] = Rn(l, this.o, this.zone);
         return Ya(this, {
            ts: c,
            o: f
         })
      }
      plus(t) {
         if (!this.isValid) return this;
         let a = Te.fromDurationLike(t);
         return Ya(this, iu(this, a))
      }
      minus(t) {
         if (!this.isValid) return this;
         let a = Te.fromDurationLike(t).negate();
         return Ya(this, iu(this, a))
      }
      startOf(t) {
         if (!this.isValid) return this;
         let a = {},
            r = Te.normalizeUnit(t);
         switch (r) {
            case "years":
               a.month = 1;
            case "quarters":
            case "months":
               a.day = 1;
            case "weeks":
            case "days":
               a.hour = 0;
            case "hours":
               a.minute = 0;
            case "minutes":
               a.second = 0;
            case "seconds":
               a.millisecond = 0;
               break;
            case "milliseconds":
               break
         }
         if (r === "weeks" && (a.weekday = 1), r === "quarters") {
            let n = Math.ceil(this.month / 3);
            a.month = (n - 1) * 3 + 1
         }
         return this.set(a)
      }
      endOf(t) {
         return this.isValid ? this.plus({
            [t]: 1
         }).startOf(t).minus(1) : this
      }
      toFormat(t, a = {}) {
         return this.isValid ? De.create(this.loc.redefaultToEN(a)).formatDateTimeFromString(this, t) : Yi
      }
      toLocaleString(t = Xt, a = {}) {
         return this.isValid ? De.create(this.loc.clone(a), t).formatDateTime(this) : Yi
      }
      toLocaleParts(t = {}) {
         return this.isValid ? De.create(this.loc.clone(t), t).formatDateTimeParts(this) : []
      }
      toISO({
         format: t = "extended",
         suppressSeconds: a = !1,
         suppressMilliseconds: r = !1,
         includeOffset: n = !0,
         extendedZone: i = !1
      } = {}) {
         if (!this.isValid) return null;
         let s = t === "extended",
            o = Qi(this, s);
         return o += "T", o += su(this, s, a, r, n, i), o
      }
      toISODate({
         format: t = "extended"
      } = {}) {
         return this.isValid ? Qi(this, t === "extended") : null
      }
      toISOWeekDate() {
         return Dn(this, "kkkk-'W'WW-c")
      }
      toISOTime({
         suppressMilliseconds: t = !1,
         suppressSeconds: a = !1,
         includeOffset: r = !0,
         includePrefix: n = !1,
         extendedZone: i = !1,
         format: s = "extended"
      } = {}) {
         return this.isValid ? (n ? "T" : "") + su(this, s === "extended", a, t, r, i) : null
      }
      toRFC2822() {
         return Dn(this, "EEE, dd LLL yyyy HH:mm:ss ZZZ", !1)
      }
      toHTTP() {
         return Dn(this.toUTC(), "EEE, dd LLL yyyy HH:mm:ss 'GMT'")
      }
      toSQLDate() {
         return this.isValid ? Qi(this, !0) : null
      }
      toSQLTime({
         includeOffset: t = !0,
         includeZone: a = !1,
         includeOffsetSpace: r = !0
      } = {}) {
         let n = "HH:mm:ss.SSS";
         return (a || t) && (r && (n += " "), a ? n += "z" : t && (n += "ZZ")), Dn(this, n, !0)
      }
      toSQL(t = {}) {
         return this.isValid ? `${this.toSQLDate()} ${this.toSQLTime(t)}` : null
      }
      toString() {
         return this.isValid ? this.toISO() : Yi
      }
      valueOf() {
         return this.toMillis()
      }
      toMillis() {
         return this.isValid ? this.ts : NaN
      }
      toSeconds() {
         return this.isValid ? this.ts / 1e3 : NaN
      }
      toUnixInteger() {
         return this.isValid ? Math.floor(this.ts / 1e3) : NaN
      }
      toJSON() {
         return this.toISO()
      }
      toBSON() {
         return this.toJSDate()
      }
      toObject(t = {}) {
         if (!this.isValid) return {};
         let a = {
            ...this.c
         };
         return t.includeConfig && (a.outputCalendar = this.outputCalendar, a.numberingSystem = this.loc.numberingSystem, a.locale = this.loc.locale), a
      }
      toJSDate() {
         return new Date(this.isValid ? this.ts : NaN)
      }
      diff(t, a = "milliseconds", r = {}) {
         if (!this.isValid || !t.isValid) return Te.invalid("created by diffing an invalid DateTime");
         let n = {
               locale: this.locale,
               numberingSystem: this.numberingSystem,
               ...r
            },
            i = Eo(a).map(Te.normalizeUnit),
            s = t.valueOf() > this.valueOf(),
            o = s ? this : t,
            u = s ? t : this,
            l = qo(o, u, i, n);
         return s ? l.negate() : l
      }
      diffNow(t = "milliseconds", a = {}) {
         return this.diff(e.now(), t, a)
      }
      until(t) {
         return this.isValid ? zt.fromDateTimes(this, t) : this
      }
      hasSame(t, a) {
         if (!this.isValid) return !1;
         let r = t.valueOf(),
            n = this.setZone(t.zone, {
               keepLocalTime: !0
            });
         return n.startOf(a) <= r && r <= n.endOf(a)
      }
      equals(t) {
         return this.isValid && t.isValid && this.valueOf() === t.valueOf() && this.zone.equals(t.zone) && this.loc.equals(t.loc)
      }
      toRelative(t = {}) {
         if (!this.isValid) return null;
         let a = t.base || e.fromObject({}, {
               zone: this.zone
            }),
            r = t.padding ? this < a ? -t.padding : t.padding : 0,
            n = ["years", "months", "days", "hours", "minutes", "seconds"],
            i = t.unit;
         return Array.isArray(t.unit) && (n = t.unit, i = void 0), lu(a, this.plus(r), {
            ...t,
            numeric: "always",
            units: n,
            unit: i
         })
      }
      toRelativeCalendar(t = {}) {
         return this.isValid ? lu(t.base || e.fromObject({}, {
            zone: this.zone
         }), this, {
            ...t,
            numeric: "auto",
            units: ["years", "months", "days"],
            calendary: !0
         }) : null
      }
      static min(...t) {
         if (!t.every(e.isDateTime)) throw new Ne("min requires all arguments be DateTimes");
         return _i(t, a => a.valueOf(), Math.min)
      }
      static max(...t) {
         if (!t.every(e.isDateTime)) throw new Ne("max requires all arguments be DateTimes");
         return _i(t, a => a.valueOf(), Math.max)
      }
      static fromFormatExplain(t, a, r = {}) {
         let {
            locale: n = null,
            numberingSystem: i = null
         } = r, s = he.fromOpts({
            locale: n,
            numberingSystem: i,
            defaultToEN: !0
         });
         return Ki(s, t, a)
      }
      static fromStringExplain(t, a, r = {}) {
         return e.fromFormatExplain(t, a, r)
      }
      static get DATE_SHORT() {
         return Xt
      }
      static get DATE_MED() {
         return Ca
      }
      static get DATE_MED_WITH_WEEKDAY() {
         return pi
      }
      static get DATE_FULL() {
         return xa
      }
      static get DATE_HUGE() {
         return Ta
      }
      static get TIME_SIMPLE() {
         return Sa
      }
      static get TIME_WITH_SECONDS() {
         return Ia
      }
      static get TIME_WITH_SHORT_OFFSET() {
         return ba
      }
      static get TIME_WITH_LONG_OFFSET() {
         return Aa
      }
      static get TIME_24_SIMPLE() {
         return Ba
      }
      static get TIME_24_WITH_SECONDS() {
         return wa
      }
      static get TIME_24_WITH_SHORT_OFFSET() {
         return Na
      }
      static get TIME_24_WITH_LONG_OFFSET() {
         return _a
      }
      static get DATETIME_SHORT() {
         return Da
      }
      static get DATETIME_SHORT_WITH_SECONDS() {
         return Ra
      }
      static get DATETIME_MED() {
         return La
      }
      static get DATETIME_MED_WITH_SECONDS() {
         return ka
      }
      static get DATETIME_MED_WITH_WEEKDAY() {
         return yi
      }
      static get DATETIME_FULL() {
         return Oa
      }
      static get DATETIME_FULL_WITH_SECONDS() {
         return Ua
      }
      static get DATETIME_HUGE() {
         return Fa
      }
      static get DATETIME_HUGE_WITH_SECONDS() {
         return Pa
      }
   };

   function $r(e) {
      if (ie.isDateTime(e)) return e;
      if (e && e.valueOf && _t(e.valueOf())) return ie.fromJSDate(e);
      if (e && typeof e == "object") return ie.fromObject(e);
      throw new Ne(`Unknown datetime argument: ${e}, of type ${typeof e}`)
   }
   var yr = Ea(ha(), 1);
   var Lc = (e, t, a = []) => {
         let r = Object.getOwnPropertyDescriptors(t);
         for (let n of a) delete r[n];
         Object.defineProperties(e, r)
      },
      da = (e, t = [e]) => {
         let a = Object.getPrototypeOf(e);
         return a === null ? t : da(a, [...t, a])
      },
      Xp = (...e) => {
         if (e.length === 0) return;
         let t, a = e.map(r => da(r));
         for (; a.every(r => r.length > 0);) {
            let r = a.map(i => i.pop()),
               n = r[0];
            if (r.every(i => i === n)) t = n;
            else break
         }
         return t
      },
      Nc = (e, t, a = []) => {
         var r;
         let n = (r = Xp(...e)) !== null && r !== void 0 ? r : Object.prototype,
            i = Object.create(n),
            s = da(n);
         for (let o of e) {
            let u = da(o);
            for (let l = u.length - 1; l >= 0; l--) {
               let c = u[l];
               s.indexOf(c) === -1 && (Lc(i, c, ["constructor", ...a]), s.push(c))
            }
         }
         return i.constructor = t, i
      },
      Js = e => e.filter((t, a) => e.indexOf(t) == a),
      fi = (e, t) => {
         let a = t.map(i => da(i)),
            r = 0,
            n = !0;
         for (; n;) {
            n = !1;
            for (let i = t.length - 1; i >= 0; i--) {
               let s = a[i][r];
               if (s != null && (n = !0, Object.getOwnPropertyDescriptor(s, e) != null)) return a[i][0]
            }
            r++
         }
      },
      kc = (e, t = Object.prototype) => new Proxy({}, {
         getPrototypeOf() {
            return t
         },
         setPrototypeOf() {
            throw Error("Cannot set prototype of Proxies created by ts-mixer")
         },
         getOwnPropertyDescriptor(a, r) {
            return Object.getOwnPropertyDescriptor(fi(r, e) || {}, r)
         },
         defineProperty() {
            throw new Error("Cannot define new properties on Proxies created by ts-mixer")
         },
         has(a, r) {
            return fi(r, e) !== void 0 || t[r] !== void 0
         },
         get(a, r) {
            return (fi(r, e) || t)[r]
         },
         set(a, r, n) {
            let i = fi(r, e);
            if (i === void 0) throw new Error("Cannot set new properties on Proxies created by ts-mixer");
            return i[r] = n, !0
         },
         deleteProperty() {
            throw new Error("Cannot delete properties on Proxies created by ts-mixer")
         },
         ownKeys() {
            return e.map(Object.getOwnPropertyNames).reduce((a, r) => r.concat(a.filter(n => r.indexOf(n) < 0)))
         }
      }),
      Jp = (e, t) => kc([...e, {
         constructor: t
      }]),
      fn = {
         initFunction: null,
         staticsStrategy: "copy",
         prototypeStrategy: "copy",
         decoratorInheritance: "deep"
      },
      Oc = new Map,
      ey = e => Oc.get(e),
      ty = (e, t) => Oc.set(e, t);
   var _c = (e, t) => {
         var a, r;
         let n = Js([...Object.getOwnPropertyNames(e), ...Object.getOwnPropertyNames(t)]),
            i = {};
         for (let s of n) i[s] = Js([...(a = e?.[s]) !== null && a !== void 0 ? a : [], ...(r = t?.[s]) !== null && r !== void 0 ? r : []]);
         return i
      },
      Dc = (e, t) => {
         var a, r, n, i;
         return {
            property: _c((a = e?.property) !== null && a !== void 0 ? a : {}, (r = t?.property) !== null && r !== void 0 ? r : {}),
            method: _c((n = e?.method) !== null && n !== void 0 ? n : {}, (i = t?.method) !== null && i !== void 0 ? i : {})
         }
      },
      Uc = (e, t) => {
         var a, r, n, i, s, o;
         return {
            class: Js([...(a = e?.class) !== null && a !== void 0 ? a : [], ...(r = t?.class) !== null && r !== void 0 ? r : []]),
            static: Dc((n = e?.static) !== null && n !== void 0 ? n : {}, (i = t?.static) !== null && i !== void 0 ? i : {}),
            instance: Dc((s = e?.instance) !== null && s !== void 0 ? s : {}, (o = t?.instance) !== null && o !== void 0 ? o : {})
         }
      },
      eo = new Map,
      ry = (...e) => {
         var t;
         let a = new Set,
            r = new Set([...e]);
         for (; r.size > 0;)
            for (let n of r) {
               let i = da(n.prototype).map(l => l.constructor),
                  s = (t = ey(n)) !== null && t !== void 0 ? t : [],
                  u = [...i, ...s].filter(l => !a.has(l));
               for (let l of u) r.add(l);
               a.add(n), r.delete(n)
            }
         return [...a]
      },
      ay = (...e) => {
         let t = ry(...e).map(a => eo.get(a)).filter(a => !!a);
         return t.length == 0 ? {} : t.length == 1 ? t[0] : t.reduce((a, r) => Uc(a, r))
      },
      ny = (...e) => {
         let t = e.map(a => iy(a));
         return t.length === 0 ? {} : t.length === 1 ? t[0] : t.reduce((a, r) => Uc(a, r))
      },
      iy = e => {
         let t = eo.get(e);
         return t || (t = {}, eo.set(e, t)), t
      };

   function Tt(...e) {
      var t, a, r;
      let n = e.map(u => u.prototype),
         i = fn.initFunction;
      if (i !== null) {
         let u = n.map(f => f[i]).filter(f => typeof f == "function"),
            l = function(...f) {
               for (let y of u) y.apply(this, f)
            },
            c = {
               [i]: l
            };
         n.push(c)
      }

      function s(...u) {
         for (let l of e) Lc(this, new l(...u));
         i !== null && typeof this[i] == "function" && this[i].apply(this, u)
      }
      s.prototype = fn.prototypeStrategy === "copy" ? Nc(n, s) : Jp(n, s), Object.setPrototypeOf(s, fn.staticsStrategy === "copy" ? Nc(e, null, ["prototype"]) : kc(e, Function.prototype));
      let o = s;
      if (fn.decoratorInheritance !== "none") {
         let u = fn.decoratorInheritance === "deep" ? ay(...e) : ny(...e);
         for (let l of (t = u?.class) !== null && t !== void 0 ? t : []) {
            let c = l(o);
            c && (o = c)
         }
         Rc((a = u?.static) !== null && a !== void 0 ? a : {}, o), Rc((r = u?.instance) !== null && r !== void 0 ? r : {}, o.prototype)
      }
      return ty(o, e), o
   }
   var Rc = (e, t) => {
      let a = e.property,
         r = e.method;
      if (a)
         for (let n in a)
            for (let i of a[n]) i(t, n);
      if (r)
         for (let n in r)
            for (let i of r[n]) i(t, n, Object.getOwnPropertyDescriptor(t, n))
   };
   var to = e => (typeof e == "number" || e instanceof Number || typeof e == "string" && !Number.isNaN(e)) && Number.isFinite(e);
   var hi = e => /boolean|number|string/.test(typeof e);
   var Dr = class {
      extractScalar(t, a) {
         let r = this._dataArray[t] ?? a;
         return hi(r) ? r : a
      }
      extractString(t) {
         return this.extractScalar(t, "").toString()
      }
      extractInteger(t) {
         let a = this.extractScalar(t, 0);
         return to(a) ? Math.floor(Number(a)) : 0
      }
      extractArray(t) {
         let a = this._dataArray[t] ?? null;
         return typeof a == "object" && a !== null ? a : {}
      }
      extractArrayStrings(t) {
         let a = {};
         for (let [r, n] of Object.entries(this.extractArray(t))) hi(n) && (a[r] = n.toString());
         return a
      }
      extractDateTime(t) {
         return ie.fromMillis(this.extractInteger(t) * 1e3)
      }
   };
   var ft = class {
      static localFileOpen(t) {
         if (typeof window < "u") throw new TypeError("M\xE9todo no disponible en browser");
         if (t.startsWith("file://") && (t = t.slice(7)), t === "") throw new Error("The file to open is empty");
         if (/(ftp|http|https):\/\/(\w+:?\w*@)?(\S+)(:\d+)?(\/|\/([\w#!:.?+=&%@\-/]))?/.test(t)) throw new Error("Invalid scheme to open file");
         let a = gn("node:fs"),
            r = "";
         try {
            r = a.realpathSync(t)
         } catch {
            throw new Error("Unable to locate the file to open")
         }
         let n = "";
         try {
            n = a.readFileSync(r, "binary")
         } catch {
            throw new Error("File content is empty")
         }
         return n
      }
   };
   var hn = class e {
      static LeadChars = [" ", "#"];
      static LeadReplacements = ["\\20", "\\22"];
      static TrailChars = [" "];
      static TrailReplacements = ["\\20"];
      static InnerChars = [/\\/g, /"/g, /\+/g, /,/g, /;/g, /</g, /=/g, />/g];
      static InnerReplacements = ["\\5C", "\\22", "\\2b", "\\2c", "\\3b", "\\3c", "\\3d", "\\3e"];
      escape(t) {
         let a = "",
            r = "",
            n = (o, u, l) => {
               let c = l;
               for (let [f, y] of o.entries()) c = c.replace(y, u[f]);
               return c
            },
            i = t.slice(0, 1);
         e.LeadChars.includes(i) && (a = n(e.LeadChars, e.LeadReplacements, i), t = t.slice(1));
         let s = t.slice(-1);
         return e.TrailChars.includes(s) && (r = n(e.TrailChars, e.TrailReplacements, s), t = t.slice(0, -1)), `${a}${n(e.InnerChars,e.InnerReplacements,t)}${r}`
      }
      escapeRecord(t) {
         return Object.entries(t).map(([a, r]) => `${this.escape(a)}=${this.escape(r)}`).join(",")
      }
   };
   var di = (a => (a.FIEL = "FIEL", a.CSD = "CSD", a))(di || {}),
      pa = class {
         type;
         constructor(t) {
            if (!(t in di)) throw new Error("Index Not Found");
            this.type = t
         }
         isFiel() {
            return this.type === "FIEL"
         }
         isCsd() {
            return this.type === "CSD"
         }
      };
   var Rr = class {
      contents;
      constructor(t) {
         this.contents = t
      }
      getContents() {
         return this.contents
      }
      extractCertificate() {
         return this.extractBase64("CERTIFICATE")
      }
      extractPublicKey() {
         return this.extractBase64("PUBLIC KEY")
      }
      extractPrivateKey() {
         let t = this.extractBase64("PRIVATE KEY");
         return t !== "" || (t = this.extractBase64("RSA PRIVATE KEY"), t !== "") || (t = this.extractRsaProtected(), t !== "") ? t : this.extractBase64("ENCRYPTED PRIVATE KEY")
      }
      extractBase64(t) {
         t = t.replaceAll(/[!$()*+./:<=>?[\\\]^{|}-]/g, "\\$&");
         let a = `^-----BEGIN ${t}-----\r?
([A-Za-z0-9+/=]+\r?
)+-----END ${t}-----\r?
?$`,
            r = new RegExp(a, "m").exec(this.getContents());
         return this.normalizeLineEndings(`${r?r[0]:""}`)
      }
      extractRsaProtected() {
         let t = `^-----BEGIN RSA PRIVATE KEY-----\r?
Proc-Type: .+\r?
DEK-Info: .+\r?
\r?
([A-Za-z0-9+/=]+\r?
)+-----END RSA PRIVATE KEY-----\r?
?$`,
            a = new RegExp(t, "m").exec(this.getContents());
         return this.normalizeLineEndings(`${a?a[0]:""}`)
      }
      normalizeLineEndings(t) {
         return t.replaceAll(`\r
`, `
`)
      }
   };
   var pn = Ea(ha(), 1);
   var ya = (r => (r.RSA = "RSA", r.DSA = "DSA", r.ECDSA = "ECDSA", r))(ya || {}),
      dn = class {
         type;
         constructor(t) {
            if (!(t in ya)) throw new Error("Index Not Found");
            this.type = t
         }
         isRSA() {
            return this.type === "RSA"
         }
         isDSA() {
            return this.type === "DSA"
         }
         isECDSA() {
            return this.type === "ECDSA"
         }
         value() {
            return this.type
         }
      };
   var Lr = class extends Tt(Dr) {
      typeKey;
      constructor(t) {
         super(), this._dataArray = t
      }
      get type() {
         return this.typeKey || (this.typeKey = new dn(this.extractString("type") || "RSA")), this.typeKey
      }
      parsed() {
         return this._dataArray
      }
      publicKeyContents() {
         return this.extractString("key")
      }
      numberOfBits() {
         return this.extractInteger("bits")
      }
      typeData() {
         return this.extractArray(this.type.value())
      }
      isType(t) {
         return this.type.value() === t
      }
   };
   var kr = class e extends Tt(Lr, ft) {
      constructor(t) {
         let a = e.callOnPublicKeyWithContents(r => {
            let n = pn.default.pki.publicKeyToPem(r),
               i = {};
            return i.bits = r.n.bitLength(), i.key = n, i.RSA = r, i.type = "RSA", i
         }, t);
         super(a)
      }
      static openFile(t) {
         return new e(e.localFileOpen(t))
      }
      static callOnPublicKeyWithContents(t, a) {
         let r, n = "";
         try {
            r = pn.default.pki.certificateFromPem(a).publicKey
         } catch (i) {
            n = `Cannot open public key: ${i.message}`, r = void 0
         }
         if (!r) try {
            r = pn.default.pki.publicKeyFromPem(a)
         } catch (i) {
            n = `Cannot open public key: ${i.message}`, r = void 0
         }
         if (!r) throw new Error(n);
         return t(r)
      }
      verify(t, a, r = "sha256") {
         return this.callOnPublicKey(n => {
            try {
               let i = pn.default.md[r].create();
               return i.update(t), n.verify(i.digest().bytes(), a)
            } catch (i) {
               throw new Error(`Verify error ${i.message}`)
            }
         })
      }
      callOnPublicKey(t) {
         return e.callOnPublicKeyWithContents(t, this.publicKeyContents())
      }
   };
   var sy = class ro {
         _sequence;
         _length;
         constructor(t) {
            ro.checkIsValid(t), this._sequence = t.toUpperCase(), this._length = new TextEncoder().encode(t).byteLength
         }
         static isValid(t) {
            try {
               return ro.checkIsValid(t), !0
            } catch {
               return !1
            }
         }
         static checkIsValid(t) {
            let a = new TextEncoder().encode(t).byteLength;
            if (a < 2) throw new Error("Sequence does not contains enough elements");
            if (a !== t.length) throw new Error("Cannot use multibyte strings in dictionary");
            if ([...t.toUpperCase()].some((r, n, i) => i.lastIndexOf(r) !== n)) throw new Error("The sequence has not unique values")
         }
         toString = () => this._sequence;
         value() {
            return this._sequence
         }
         length() {
            return this._length
         }
      },
      ao = class Fc {
         _sequence;
         constructor(t) {
            this._sequence = t
         }
         static createBase36() {
            return new Fc(new sy("0123456789abcdefghijklmnopqrstuvwxyz"))
         }
         sequence() {
            return this._sequence
         }
         maximumBase() {
            return this._sequence.length()
         }
         convert(t, a, r) {
            if (a = Math.floor(a), r = Math.floor(r), t = t.toUpperCase(), a < 2 || a > this.maximumBase()) throw new Error("Invalid from base");
            if (r < 2 || r > this.maximumBase()) throw new Error("Invalid to base");
            let n = this.sequence().value();
            t === "" && (t = n[0]);
            let i = n.slice(0, Math.max(0, a));
            if (!new RegExp(`^[${i}]+$`).test(t)) throw new Error("The number to convert contains invalid characters");
            let {
               length: s
            } = t, o = [];
            for (let c = 0; c < s; c++) o.push(n.indexOf(t.charAt(c)));
            let u = "",
               l = 0;
            do {
               let c = 0;
               l = 0;
               for (let f = 0; f < s; f++) c = c * a + o[f], c >= r ? (o[l] = Math.floor(c / r), c %= r, l += 1) : l > 0 && (o[l] = 0, l += 1);
               s = l, u = `${n[c]}${u}`
            } while (l > 0);
            return u
         }
      };
   var Or = class e {
      _hexadecimal;
      constructor(t) {
         if (t === "") throw new Error("The hexadecimal string is empty");
         if ("0x".toLowerCase() === t.slice(0, 2).toLowerCase() && (t = t.slice(2)), !/^[\da-f]*$/.test(t)) throw new Error("The hexadecimal string contains invalid characters");
         this._hexadecimal = t
      }
      static createFromHexadecimal(t) {
         return new e(t)
      }
      static createFromDecimal(t) {
         let a = ao.createBase36().convert(t, 10, 16);
         return new e(a)
      }
      static createFromBytes(t) {
         let a = (t.match(/./g) ?? []).map(r => {
            let n = r.codePointAt(0) ?? 0;
            return Number.parseInt(`${n}`, 10).toString(16)
         }).join("");
         return new e(a)
      }
      hexadecimal() {
         return this._hexadecimal
      }
      bytes() {
         return (this._hexadecimal.match(/.{1,2}/g) ?? []).map(t => {
            let a = t.replaceAll(/[^\da-f]/gi, ""),
               r = Number.parseInt(a, 16);
            return String.fromCodePoint(r)
         }).join("")
      }
      decimal() {
         return ao.createBase36().convert(this.hexadecimal(), 16, 10)
      }
   };
   var ma = class e extends Tt(Dr, ft) {
      _pem;
      _rfc;
      _legalName;
      _serialNumber;
      _publicKey;
      constructor(t) {
         if (super(), t === "") throw new SyntaxError("Create certificate from empty contents");
         let a = new Rr(t).extractCertificate();
         a === "" && (a = e.convertDerToPem(t));
         let r;
         try {
            r = yr.default.pki.certificateFromPem(a)
         } catch (n) {
            throw new Error(`Cannot parse X509 certificate from contents ${n.message}`)
         }
         this._pem = a, this._dataArray = {
            version: r.version,
            serialNumber: r.serialNumber,
            subject: r.subject,
            issuer: r.issuer,
            extensions: r.extensions,
            validity: r.validity
         }, this._rfc = yr.default.util.decodeUtf8(`${this.subjectData({type:"2.5.4.45"})?.value}`.split(" ")[0]), this._legalName = this.subjectData({
            type: "2.5.4.41"
         })?.value, this._dataArray.hash = r.issuer.hash, this._dataArray.signatureTypeLN = r.signature
      }
      static convertDerToPem(t) {
         return t !== yr.default.util.encode64(yr.default.util.decode64(t)) && (t = yr.default.util.encode64(t)), [`-----BEGIN CERTIFICATE-----
`, `${(t.match(/.{1,64}/g)??[]).join(`
            `)}
`, "-----END CERTIFICATE-----"
         ].join("")
      }
      static openFile(t) {
         return new e(e.localFileOpen(t))
      }
      pem() {
         return this._pem
      }
      pemAsOneLine() {
         return this.pem().replaceAll(`\r
`, `
`).split(/\n/).filter(n => /^((?!-).)*$/.test(n)).join("")
      }
      parsed() {
         return this._dataArray
      }
      rfc() {
         return this._rfc
      }
      legalName() {
         return this._legalName
      }
      branchName() {
         return this.subjectData({
            shortName: "OU"
         })?.value ?? ""
      }
      name() {
         return yr.default.util.decodeUtf8(`/CN=${this.subjectData({shortName:"CN"})?.value??""}`)
      }
      subject() {
         return this.extractArray("subject")
      }
      subjectData(t) {
         return this.subject().getField(t)
      }
      hash() {
         return this.extractString("hash")
      }
      issuer() {
         return this.extractArray("issuer")
      }
      issuerData(t) {
         return this.issuer().getField(t)
      }
      version() {
         return this.extractString("version")
      }
      serialNumber() {
         if (!this._serialNumber) {
            let t = this.extractString("serialNumber");
            this._serialNumber = this.createSerialNumber(t, "")
         }
         return this._serialNumber
      }
      validity() {
         return this.extractArray("validity")
      }
      validFrom() {
         return this.validity().notBefore
      }
      validTo() {
         return this.validity().notAfter
      }
      validFromDateTime() {
         return ie.fromJSDate(this.validFrom())
      }
      validToDateTime() {
         return ie.fromJSDate(this.validTo())
      }
      signatureTypeLN() {
         return this.extractString("signatureTypeLN")
      }
      extensions() {
         return this._dataArray.ext
      }
      publicKey() {
         return this._publicKey || (this._publicKey = new kr(this.pem())), this._publicKey
      }
      satType() {
         return this.branchName() === "" ? new pa("FIEL") : new pa("CSD")
      }
      validOn(t) {
         return t || (t = ie.now()), t.toMillis() >= this.validFromDateTime().toMillis() && t.toMillis() <= this.validToDateTime().toMillis()
      }
      issuerAsRfc4514() {
         let t = {},
            a = this.issuer();
         for (let r of Object.values(a.attributes)) {
            !r.shortName && !r.type || (t[r.shortName ?? r.type ?? ""] = yr.default.util.decodeUtf8(r.value))
         }
         return new hn().escapeRecord(t)
      }
      createSerialNumber(t, a) {
         if (t !== "") return Or.createFromHexadecimal(t);
         if (a !== "") return a.slice(0, 2).toLowerCase() === "0x".toLowerCase() ? Or.createFromHexadecimal(a.slice(2)) : Or.createFromDecimal(a);
         throw new Error("Certificate does not contain a serial number")
      }
   };
   var mr = Ea(ha(), 1);
   var ga = class e extends Tt(Lr, ft) {
      _pem;
      _passPhrase;
      _publicKey;
      constructor(t, a) {
         if (super(), t === "") throw new SyntaxError("Private key is empty");
         let n = new Rr(t).extractPrivateKey();
         if (n === "") {
            let i = a !== "";
            n = e.convertDerToPem(t, i)
         }
         this._pem = n, this._passPhrase = a, this._dataArray = this.callOnPrivateKey(i => {
            let s = {},
               o = mr.default.pki.setRsaPublicKey(i.n, i.e);
            return s.bits = i.n.bitLength(), s.key = mr.default.pki.publicKeyToPem(o), s.RSA = i, s.type = "RSA", s
         })
      }
      static convertDerToPem(t, a) {
         let r = a ? "ENCRYPTED PRIVATE KEY" : "PRIVATE KEY";
         return [`-----BEGIN ${r}-----
`, `${(mr.default.util.encode64(t).match(/.{1,64}/g)??[]).join(`
            `)}
`, `-----END ${r}-----`
         ].join("")
      }
      static openFile(t, a) {
         return new e(e.localFileOpen(t), a)
      }
      pem() {
         return this._pem
      }
      passPhrase() {
         return this._passPhrase
      }
      publicKey() {
         return this._publicKey || (this._publicKey = new kr(this.publicKeyContents())), this._publicKey
      }
      sign(t, a = "sha256") {
         if (t.length === 0) throw new Error("Cannot sign data: empty signature");
         return this.callOnPrivateKey(r => {
            try {
               let n = mr.default.md[a].create();
               return n.update(t), r.sign(n)
            } catch {
               throw new Error("Cannot sign data: empty signature")
            }
         })
      }
      belongsTo(t) {
         return this.belongsToPEMCertificate(t.pem())
      }
      belongsToPEMCertificate(t) {
         let a = mr.default.pki.publicKeyFromPem(this.publicKeyContents()),
            n = mr.default.pki.certificateFromPem(t).publicKey;
         return JSON.stringify(n) === JSON.stringify(a)
      }
      callOnPrivateKey(t) {
         let a;
         try {
            a = mr.default.pki.decryptRsaPrivateKey(this._pem, this._passPhrase)
         } catch (r) {
            throw new Error(`Cannot open private key: ${r.message}`)
         }
         if (!a) throw new Error("Cannot open private key: invalid key or password");
         return t(a)
      }
   };
   var yn = class e {
      _certificate;
      _privateKey;
      constructor(t, a) {
         if (!a.belongsTo(t)) throw new Error("Certificate does not belong to private key");
         this._certificate = t, this._privateKey = a
      }
      static create(t, a, r) {
         let n = new ma(t),
            i = new ga(a, r);
         return new e(n, i)
      }
      static openFiles(t, a, r) {
         let n = ma.openFile(t),
            i = ga.openFile(a, r);
         return new e(n, i)
      }
      certificate() {
         return this._certificate
      }
      privateKey() {
         return this._privateKey
      }
      rfc() {
         return this._certificate.rfc()
      }
      legalName() {
         return this._certificate.legalName()
      }
      isFiel() {
         return this._certificate.satType().isFiel()
      }
      isCsd() {
         return this._certificate.satType().isCsd()
      }
      sign(t, a = "sha256") {
         return this._privateKey.sign(t, a)
      }
      verify(t, a, r = "sha256") {
         return this._certificate.publicKey().verify(t, a, r)
      }
   };
   var va = Ea(ha(), 1);
   var no = class extends Tt(ft) {
      _credential;
      constructor(t) {
         super(), this._credential = t
      }
      getCredential() {
         return this._credential
      }
      export (t, a) {
         let r = this.getPfxFromCredential(t, a);
         return va.default.asn1.toDer(r).getBytes()
      }
      exportToBase64(t, a) {
         return va.default.util.encode64(this.export(t, a))
      }
      getPfxFromCredential(t, a) {
         try {
            let r = va.default.pki.decryptRsaPrivateKey(this._credential.privateKey().pem(), this._credential.privateKey().passPhrase()),
               n = va.default.pki.certificateFromPem(this._credential.certificate().pem());
            return va.default.pkcs12.toPkcs12Asn1(r, [n], t, {
               algorithm: a
            })
         } catch {
            throw new Error(`Cannot export credential with certificate ${this._credential.certificate().serialNumber().bytes()}`)
         }
      }
   };
   var jt = Ea(ha(), 1);
   var io = class extends Tt(ft) {
      static createCredentialFromContents(t, a) {
         if (t === "") throw new Error("Cannot create credential from empty PFX contents");
         let r = this.loadPkcs12(t, a);
         return yn.create(jt.default.pki.certificateToPem(r.cert), jt.default.pki.privateKeyToPem(r.pKey), "")
      }
      static createCredentialFromFile(t, a) {
         return this.createCredentialFromContents(this.localFileOpen(t), a)
      }
      static loadPkcs12(t, a = "") {
         try {
            let r = jt.default.asn1.fromDer(t),
               n = jt.default.pkcs12.pkcs12FromAsn1(r, a),
               s = n.getBags({
                  bagType: jt.default.pki.oids.certBag
               })[jt.default.pki.oids.certBag][0],
               {
                  cert: o
               } = s,
               l = n.getBags({
                  bagType: jt.default.pki.oids.pkcs8ShroudedKeyBag
               })[jt.default.pki.oids.pkcs8ShroudedKeyBag][0],
               {
                  key: c
               } = l;
            return {
               cert: o,
               pKey: c
            }
         } catch {
            throw new Error("Invalid PKCS#12 contents or wrong passphrase")
         }
      }
   };
   return Gc(oy);
})();
/* istanbul ignore if -- @preserve */
/* istanbul ignore if: on certs not pass but library check for undefined -- @preserve */
/* istanbul ignore next: really dificult fail sign process -- @preserve */
//# sourceMappingURL=credentials.global.js.map

if (typeof(module) == "object" && typeof(module.exports) == "object") {
   module.exports = credentials;
}