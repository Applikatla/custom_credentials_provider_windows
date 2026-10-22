#pragma once

#include "common.h"

class ClassFactory : public IClassFactory {
public:
  ClassFactory();
  virtual ~ClassFactory();

  // IUnknown
  IFACEMETHODIMP QueryInterface(REFIID riid, void **ppv) override;
  IFACEMETHODIMP_(ULONG) AddRef() override;
  IFACEMETHODIMP_(ULONG) Release() override;

  // IClassFactory
  IFACEMETHODIMP CreateInstance(IUnknown *pUnkOuter, REFIID riid,
                                void **ppv) override;
  IFACEMETHODIMP LockServer(BOOL fLock) override;

private:
  LONG m_cRef;
};
