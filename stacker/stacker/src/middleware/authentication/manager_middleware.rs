use crate::helpers::JsonResponse;
use crate::middleware::authentication::*;
use crate::models;
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse},
    error::ErrorBadRequest,
    Error,
};
use futures::{
    future::{FutureExt, LocalBoxFuture},
    task::{Context, Poll},
};
use std::cell::RefCell;
use std::rc::Rc;

pub struct ManagerMiddleware<S> {
    pub service: Rc<RefCell<S>>,
}

impl<S, B> Service<ServiceRequest> for ManagerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<ServiceResponse<B>, Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Ok(service) = self.service.try_borrow_mut() {
            service.poll_ready(ctx)
        } else {
            Poll::Pending
        }
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        async move {
            let _ = method::try_agent(&mut req).await?
                || method::try_jwt(&mut req).await?
                || method::try_oauth(&mut req).await?
                || method::try_query(&mut req).await?
                || method::try_cookie(&mut req).await?
                || method::try_hmac(&mut req).await?
                || method::anonym(&mut req)?;

            Ok(req)
        }
        .then(|req: Result<ServiceRequest, String>| async move {
            match req {
                Ok(req) => {
                    let fut = service.borrow_mut().call(req);
                    fut.await
                }
                Err(msg) => Err(ErrorBadRequest(
                    JsonResponse::<models::Client>::build()
                        .set_msg(msg)
                        .to_string(),
                )),
            }
        })
        .boxed_local()
    }
}
