import {Component, OnDestroy, OnInit} from '@angular/core';
import {OtpService} from "./services/otp.service";
import {interval, Subject, Subscription} from "rxjs";
import {takeUntil} from "rxjs/operators";
import {Totp} from "slauth";
import {FormControl, FormGroup} from '@angular/forms';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent  implements OnInit, OnDestroy {
  form: FormGroup;
  title = 'otp-example';
  code = null;
  issuer = 'Devolutions';
  account = 'dev@devolutions.net';
  otp: Totp = null;
  // secret is either base32 or hex
  secret = 'GEZDGNBVGY';
  // period is the duration time of a generated code
  period = 30;
  // digit is how many digit the generated code will have
  digits = 6;
  private unsubscribe$ = new Subject<void>();
  private intSub: Subscription = null;

  constructor(private otpService: OtpService) {
  }

  ngOnDestroy(): void {
    this.unsubscribe$.next();
    this.unsubscribe$.complete();
  }

  ngOnInit() {
    this.form = new FormGroup({
      issuer: new FormControl('Devolutions', []),
      account: new FormControl('dev@devolutions.net', []),
      secret: new FormControl('GEZDGNBVGY', []),
      period: new FormControl(30, []),
      digits: new FormControl(6, []),
    });

    this.applyOtpConfig()
  }

  applyOtpConfig() {
    if (this.intSub) {
      this.intSub.unsubscribe();
    }

    this.issuer = this.form.get('issuer').value;
    this.account = this.form.get('account').value;
    this.secret = this.form.get('secret').value;
    this.period = this.form.get('period').value;
    this.digits = this.form.get('digits').value;

    this.otpService.ready.pipe(takeUntil(this.unsubscribe$)).subscribe((available) => {
      console.log("loaded");
      if (!available) {return;}
      this.otp = this.otpService.module.Totp.fromParts(this.secret, this.period, this.digits, this.otpService.module.OtpAlgorithm.sha1());
      this.intSub = interval(2).pipe(takeUntil(this.unsubscribe$)).subscribe(() => {
        this.code = this.otp.generateCode();
      })
    })
  }

  getUri() {
    if (this.otp) {
      return this.otp.toUri(this.issuer, this.account);
    } else {
      return '';
    }
  }
}
