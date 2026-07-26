import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import Traces from '@/presentation/views/Traces.vue'

describe('Traces.vue', () => {
    it('renderiza el panel con el link de trazas', () => {
        const wrapper = mount(Traces)

        expect(wrapper.text()).toContain('Trazas')
        expect(wrapper.find('a.btn').exists()).toBe(true)
    })

    it('sin VITE_TRACES_URL muestra el aviso de configuración', () => {
        const wrapper = mount(Traces)

        expect(wrapper.text()).toContain('No hay URL configurada')
    })
})
